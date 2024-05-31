use std::{collections::HashMap, sync::RwLock};

use crate::bank::log_enabled;
use evm_state::{AccountProvider, EvmBackend, Executor, FromKey, Incomming};
use log::{debug, warn};
use solana_measure::measure::Measure;
use solana_sdk::{
    feature_set,
    hash::Hash,
    recent_evm_blockhashes_account,
    signature::{Keypair, Signature},
    signer::Signer,
    sysvar,
    transaction::{Result, Transaction},
};

use crate::blockhash_queue::BlockHashEvm;

use super::Bank;

pub type ChainID = u64;

#[derive(Debug, Default)]
pub struct EvmChain {
    pub(crate) chain_id: ChainID,
    pub(crate) evm_state: RwLock<evm_state::EvmState>,
    pub(crate) evm_changed_list: RwLock<Option<(evm_state::H256, evm_state::ChangedState)>>,
    pub(crate) evm_blockhashes: RwLock<BlockHashEvm>,
}

impl EvmChain {
    /// EVM Chain ID
    pub fn id(&self) -> ChainID {
        self.chain_id
    }

    pub fn set_id(&mut self, id: ChainID) {
        self.chain_id = id;
    }

    /// EVM State read-only lock
    pub fn state<'a>(&'a self) -> std::sync::RwLockReadGuard<'a, evm_state::EvmState> {
        // evm_state::EvmState
        self.evm_state
            .read()
            .expect("EVM State RwLock was poisoned")
    }

    /// EVM State read-only lock
    pub fn state_write<'a>(&'a self) -> std::sync::RwLockWriteGuard<'a, evm_state::EvmState> {
        // evm_state::EvmState
        self.evm_state
            .write()
            .expect("EVM State RwLock was poisoned")
    }

    pub fn blockhashes<'a>(&'a self) -> std::sync::RwLockReadGuard<'a, BlockHashEvm> {
        self.evm_blockhashes
            .read()
            .expect("EVM Blockhashes RwLock was poisoned")
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct EvmBank {
    pub(crate) main_chain: EvmChain,
    pub(crate) side_chains: HashMap<ChainID, EvmChain>,
}

impl EvmBank {
    pub fn new(
        evm_chain_id: ChainID,
        evm_blockhashes: BlockHashEvm,
        evm_state: evm_state::EvmState,
    ) -> Self {
        Self {
            main_chain: EvmChain {
                chain_id: evm_chain_id,
                evm_state: RwLock::new(evm_state),
                evm_changed_list: RwLock::new(None),
                evm_blockhashes: RwLock::new(evm_blockhashes),
            },
            side_chains: Default::default(),
        }
    }

    pub fn main_chain(&self) -> &EvmChain {
        &self.main_chain
    }
}

impl Bank {
    pub fn evm(&self) -> &EvmBank {
        &self.evm
    }

    pub fn evm_block(&self) -> Option<evm_state::Block> {
        self.evm.main_chain.state().get_block()
    }

    pub fn evm_state_change(&self) -> Option<(evm_state::H256, evm_state::ChangedState)> {
        self.evm
            .main_chain
            .evm_changed_list
            .read()
            .expect("change list was poisoned")
            .clone()
    }

    pub fn evm_burn_fee_activated(&self) -> bool {
        self.feature_set
            .is_active(&feature_set::velas::burn_fee::id())
    }

    pub fn transfer_evm(
        &self,
        n: u64,
        fee_payer: &Keypair,
        keypair: &evm_state::SecretKey,
        to: &evm_state::Address,
    ) -> Result<Signature> {
        let blockhash = self.last_blockhash();
        let nonce = self
            .evm()
            .main_chain()
            .state()
            .get_account_state(keypair.to_address())
            .map(|s| s.nonce)
            .unwrap_or_else(|| 0.into());
        let evm_tx = solana_evm_loader_program::evm_transfer(
            *keypair,
            *to,
            nonce,
            n.into(),
            Some(self.evm.main_chain.chain_id),
        );
        let ix = solana_evm_loader_program::send_raw_tx(
            fee_payer.pubkey(),
            evm_tx,
            None,
            solana_evm_loader_program::instructions::FeePayerType::Evm,
        );
        let tx = Transaction::new_signed_with_payer(
            &[ix],
            Some(&fee_payer.pubkey()),
            &[fee_payer],
            blockhash,
        );
        let signature = tx.signatures[0];
        self.process_transaction(&tx).map(|_| signature)
    }

    pub fn commit_evm(&self) {
        let mut measure = Measure::start("commit-evm-block-ms");

        let old_root = self.evm().main_chain().state().last_root();
        let hash = self
            .evm
            .main_chain
            .evm_state
            .write()
            .expect("evm state was poisoned")
            .try_commit(self.slot(), self.last_blockhash().to_bytes())
            .expect("failed to commit evm");

        measure.stop();
        debug!("EVM state commit took {}", measure);

        inc_new_counter_info!("commit-evm-block-ms", measure.as_ms() as usize);

        debug!(
            "Set evm state root to {:?} at block {}",
            self.evm.main_chain.evm_state.read().unwrap().last_root(),
            self.evm.main_chain.evm_state.read().unwrap().block_number()
        );

        let mut w_evm_blockhash_queue = self
            .evm
            .main_chain
            .evm_blockhashes
            .write()
            .expect("evm blockchashes poisoned");

        if let Some((hash, changes)) = hash {
            *self
                .evm
                .main_chain
                .evm_changed_list
                .write()
                .expect("change list was poisoned") = Some((old_root, changes));

            self.evm
                .main_chain
                .evm_state
                .write()
                .expect("evm state was poisoned")
                .reregister_slot(self.slot())
                .expect("Failed to change slot");
            w_evm_blockhash_queue.insert_hash(hash);
            if self.fix_recent_blockhashes_sysvar_evm() {
                self.update_recent_evm_blockhashes_locked(&w_evm_blockhash_queue);
            }
        }
    }

    // TODO: add parameter: chain_id: ChainId
    pub fn evm_hashes(&self) -> [evm_state::H256; crate::blockhash_queue::MAX_EVM_BLOCKHASHES] {
        *self
            .evm
            .main_chain
            .evm_blockhashes
            .read()
            .expect("evm_blockhashes poisoned")
            .get_hashes()
    }

    pub fn update_recent_blockhashes(&self) {
        let blockhash_queue = self.blockhash_queue.read().unwrap();
        let evm_blockhashes = self.evm.main_chain.evm_blockhashes.read().unwrap();
        self.update_recent_blockhashes_locked(&blockhash_queue);
        if !self.fix_recent_blockhashes_sysvar_evm() {
            self.update_recent_evm_blockhashes_locked(&evm_blockhashes);
        }
    }

    fn update_recent_evm_blockhashes_locked(&self, locked_blockhash_queue: &BlockHashEvm) {
        self.update_sysvar_account(&sysvar::recent_evm_blockhashes::id(), |account| {
            let mut hashes = [Hash::default(); crate::blockhash_queue::MAX_EVM_BLOCKHASHES];
            for (i, hash) in locked_blockhash_queue.get_hashes().iter().enumerate() {
                hashes[i] = Hash::new_from_array(*hash.as_fixed_bytes())
            }
            recent_evm_blockhashes_account::create_account_with_data_and_fields(
                self.inherit_specially_retained_account_fields(account),
                hashes,
            )
        });
    }

    pub fn fix_spv_proofs_evm(&self) -> bool {
        self.feature_set
            .is_active(&feature_set::velas::hardfork_pack::id())
    }

    fn fix_recent_blockhashes_sysvar_evm(&self) -> bool {
        self.feature_set
            .is_active(&feature_set::velas::hardfork_pack::id())
    }
}

impl PartialEq for EvmChain {
    fn eq(&self, other: &Self) -> bool {
        let last_root_self = self.state().last_root();
        let last_root_other = other.state().last_root();

        self.chain_id == other.chain_id && last_root_self == last_root_other
    }
}

// create factory: ExecutorFactory::new()
// struct ExecutorFactory {
//    ...
// };
// impl ExecutorFactory {
//     pub fn get_executor(&mut self, chain_id: ChainID) -> Option<Executor>;
//     pub fn destruct(self) -> Vec<(ChainId, EvmBackend)>;
// }

// deserilalizer: fn (Account) -> ChainId;
// executor_factory: fn (ChainId) -> Option<Executor>;
// executor_getter: fn (Account) -> Option<Executor> = deserializer * executor_factory

#[derive(Clone)]
pub struct EvmExecutorFactory {
    // ANCHOR - VELAS
    // TODO: add chain_id
    state_getter: fn(&Bank) -> Option<EvmBackend<Incomming>>,
}

impl EvmExecutorFactory {
    pub fn new_for_simulation() -> Self {
        Self {
            state_getter: Self::take_evm_state_form_simulation,
        }
    }

    pub fn new_for_execution() -> Self {
        Self {
            state_getter: Self::take_evm_state_cloned,
        }
    }
    // fn (ChainId) -> Option<Executor>;
    pub fn get_executor(
        &self,
        bank: &Bank,
        // chain_id: ChainID,
        evm_patch: &mut Option<EvmBackend<Incomming>>,
    ) -> Option<Executor> {
        // append to old patch if exist, or create new, from existing evm state
        *evm_patch = evm_patch.take().or_else(|| (self.state_getter)(bank));
        let last_hashes = bank.evm_hashes(/*chain_id */);
        if let Some(state) = &evm_patch {
            let evm_executor = evm_state::Executor::with_config(
                state.clone(),
                evm_state::ChainContext::new(last_hashes),
                evm_state::EvmConfig::new(
                    /*chain_id */ bank.evm().main_chain().id(),
                    bank.evm_burn_fee_activated(),
                ),
                evm_state::executor::FeatureSet::new(
                    bank.feature_set
                        .is_active(&solana_sdk::feature_set::velas::unsigned_tx_fix::id()),
                    bank.feature_set
                        .is_active(&solana_sdk::feature_set::velas::clear_logs_on_error::id()),
                    bank.feature_set.is_active(
                        &solana_sdk::feature_set::velas::accept_zero_gas_price_with_native_fee::id(
                        ),
                    ),
                ),
            );
            Some(evm_executor)
        } else {
            warn!("Executing evm transaction on already locked bank, ignoring.");
            None
        }
    }

    fn take_evm_state_cloned(bank: &Bank) -> Option<evm_state::EvmBackend<evm_state::Incomming>> {
        let is_frozen = bank.is_frozen();
        let slot = bank.slot();
        match &*bank.evm().main_chain().state() {
            evm_state::EvmState::Incomming(i) => Some(i.clone()),
            evm_state::EvmState::Committed(_) => {
                warn!(
                    "Take evm after freeze, bank_slot={}, bank_is_freeze={}",
                    slot, is_frozen
                );
                // Return None, so this transaction will fail to execute,
                // this transaction will be marked as retriable after bank realise that PoH is reached it's max height.
                None
            }
        }
    }

    fn take_evm_state_form_simulation(
        bank: &Bank,
    ) -> Option<evm_state::EvmBackend<evm_state::Incomming>> {
        match &*bank.evm().main_chain().state() {
            evm_state::EvmState::Incomming(i) => Some(i.clone()),
            evm_state::EvmState::Committed(c) => {
                debug!("Creating cloned evm state for simulation");
                Some(c.next_incomming(bank.clock().unix_timestamp as u64))
            }
        }
    }
}
