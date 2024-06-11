use crate::{bank::log_enabled, message_processor::ProcessedMessageInfo};
use evm_state::{AccountProvider, FromKey};
use log::debug;
use solana_measure::measure::Measure;
use solana_program_runtime::evm_executor_context::{
    BlockHashEvm, EvmBank, EvmExecutorContext, EvmExecutorContextType, PatchStrategy,
    MAX_EVM_BLOCKHASHES,
};
use solana_sdk::{
    feature_set,
    hash::Hash,
    recent_evm_blockhashes_account,
    signature::{Keypair, Signature},
    signer::Signer,
    sysvar,
    transaction::{Result, Transaction, TransactionError},
};

use super::Bank;

impl Bank {
    pub fn evm(&self) -> &EvmBank {
        &self.evm
    }

    pub fn evm_block(&self) -> Option<evm_state::Block> {
        self.evm.main_chain().state().get_block()
    }

    pub fn evm_state_change(&self) -> Option<(evm_state::H256, evm_state::ChangedState)> {
        self.evm.main_chain().changed_list().clone()
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
            Some(self.evm.main_chain().id()),
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
            .main_chain()
            .state_write()
            .try_commit(self.slot(), self.last_blockhash().to_bytes())
            .expect("failed to commit evm");

        measure.stop();
        debug!("EVM state commit took {}", measure);

        inc_new_counter_info!("commit-evm-block-ms", measure.as_ms() as usize);

        debug!(
            "Set evm state root to {:?} at block {}",
            self.evm.main_chain().state().last_root(),
            self.evm.main_chain().state().block_number()
        );

        let mut w_evm_blockhash_queue = self.evm.main_chain().blockhashes_write();

        if let Some((hash, changes)) = hash {
            *self.evm.main_chain().changed_list_write() = Some((old_root, changes));

            self.evm
                .main_chain()
                .state_write()
                .reregister_slot(self.slot())
                .expect("Failed to change slot");
            w_evm_blockhash_queue.insert_hash(hash);
            if self.fix_recent_blockhashes_sysvar_evm() {
                self.update_recent_evm_blockhashes_locked(&w_evm_blockhash_queue);
            }
        }
    }

    pub fn update_recent_blockhashes(&self) {
        let blockhash_queue = self.blockhash_queue.read().unwrap();
        let evm_blockhashes = self.evm.main_chain().blockhashes();
        self.update_recent_blockhashes_locked(&blockhash_queue);
        if !self.fix_recent_blockhashes_sysvar_evm() {
            self.update_recent_evm_blockhashes_locked(&evm_blockhashes);
        }
    }

    fn update_recent_evm_blockhashes_locked(&self, locked_blockhash_queue: &BlockHashEvm) {
        self.update_sysvar_account(&sysvar::recent_evm_blockhashes::id(), |account| {
            let mut hashes = [Hash::default(); MAX_EVM_BLOCKHASHES];
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

pub struct VelasEVM;

impl VelasEVM {
    pub fn context_for_simulation(bank: &Bank) -> EvmExecutorContext {
        Self::create_context(bank, EvmExecutorContextType::Simulation)
    }

    pub fn context_for_execution(bank: &Bank) -> EvmExecutorContext {
        Self::create_context(bank, EvmExecutorContextType::Execution)
    }

    // TODO: Return Result<(), E>. Let caller decide how to unwrap.
    /// # Panics
    pub fn cleanup(
        evm_executor_context: &mut EvmExecutorContext,
        process_result: &Result<ProcessedMessageInfo>,
    ) {
        if matches!(process_result, Err(TransactionError::InstructionError(..)))
            && evm_executor_context.evm_new_error_handling
        {
            evm_executor_context.cleanup(PatchStrategy::ApplyFailed)
        } else {
            evm_executor_context.cleanup(PatchStrategy::SetNew)
        }
    }

    fn create_context(bank: &Bank, context_type: EvmExecutorContextType) -> EvmExecutorContext {
        let evm = Clone::clone(bank.evm());
        let feature_set = evm_state::executor::FeatureSet::new(
            bank.feature_set
                .is_active(&solana_sdk::feature_set::velas::unsigned_tx_fix::id()),
            bank.feature_set
                .is_active(&solana_sdk::feature_set::velas::clear_logs_on_error::id()),
            bank.feature_set.is_active(
                &solana_sdk::feature_set::velas::accept_zero_gas_price_with_native_fee::id(),
            ),
        );
        let unix_timestamp = bank.clock().unix_timestamp;
        let bank_slot = bank.slot();
        let is_bank_frozen = bank.is_frozen();
        let is_evm_burn_fee_activated = bank.evm_burn_fee_activated();

        // TODO: hardcode this feature to `true`
        let evm_new_error_handling = bank
            .feature_set
            .is_active(&solana_sdk::feature_set::velas::evm_new_error_handling::id());

        let clear_logs = bank
            .feature_set
            .is_active(&solana_sdk::feature_set::velas::clear_logs_on_native_error::id());

        EvmExecutorContext::new(
            evm,
            feature_set,
            unix_timestamp,
            bank_slot,
            is_bank_frozen,
            is_evm_burn_fee_activated,
            evm_new_error_handling,
            clear_logs,
            context_type,
        )
    }
}
