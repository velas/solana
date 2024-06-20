use std::{cell::RefCell, fmt, marker::PhantomData, rc::Rc};

use serde::{
    de::{SeqAccess, Visitor},
    ser::SerializeTuple as _,
    Deserialize, Deserializer, Serialize, Serializer,
};
use solana_sdk::clock::Slot;
use std::{collections::HashMap, sync::RwLock};

use evm_state::{AccountProvider, Executor};
use log::{debug, warn};
// use solana_program_runtime::evm_executor_context::{BlockHashEvm, MAX_EVM_BLOCKHASHES};
// use solana_runtime::{bank::log_enabled, message_processor::ProcessedMessageInfo};

pub const MAX_EVM_BLOCKHASHES: usize = 256;
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct BlockHashEvm {
    #[serde(with = "BlockHashEvm")]
    hashes: [evm_state::H256; MAX_EVM_BLOCKHASHES],
}

impl BlockHashEvm {
    pub fn new() -> BlockHashEvm {
        BlockHashEvm {
            hashes: [evm_state::H256::zero(); MAX_EVM_BLOCKHASHES],
        }
    }
    pub fn get_hashes(&self) -> &[evm_state::H256; MAX_EVM_BLOCKHASHES] {
        &self.hashes
    }

    pub fn insert_hash(&mut self, hash: evm_state::H256) {
        let new_hashes = self.hashes;
        self.hashes[0..MAX_EVM_BLOCKHASHES - 1]
            .copy_from_slice(&new_hashes[1..MAX_EVM_BLOCKHASHES]);
        self.hashes[MAX_EVM_BLOCKHASHES - 1] = hash
    }

    fn deserialize<'de, D>(
        deserializer: D,
    ) -> Result<[evm_state::H256; MAX_EVM_BLOCKHASHES], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ArrayVisitor<T> {
            element: PhantomData<T>,
        }
        impl<'de, T> Visitor<'de> for ArrayVisitor<T>
        where
            T: Default + Copy + Deserialize<'de>,
        {
            type Value = [T; MAX_EVM_BLOCKHASHES];

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str(concat!("an array of length ", 256))
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<[T; MAX_EVM_BLOCKHASHES], A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut arr = [T::default(); MAX_EVM_BLOCKHASHES];
                for (i, item) in arr.iter_mut().enumerate().take(MAX_EVM_BLOCKHASHES) {
                    *item = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::invalid_length(i, &self))?;
                }
                Ok(arr)
            }
        }

        let visitor = ArrayVisitor {
            element: PhantomData,
        };
        deserializer.deserialize_tuple(MAX_EVM_BLOCKHASHES, visitor)
    }

    fn serialize<S>(
        data: &[evm_state::H256; MAX_EVM_BLOCKHASHES],
        serializer: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_tuple(data.len())?;
        for elem in &data[..] {
            seq.serialize_element(elem)?;
        }
        seq.end()
    }
}

impl Default for BlockHashEvm {
    fn default() -> Self {
        Self::new()
    }
}

pub type ChainID = u64;
pub type ChangedList = Option<(evm_state::H256, evm_state::ChangedState)>;

#[derive(Debug, Default)]
pub struct EvmChain {
    pub(crate) chain_id: ChainID,
    pub(crate) evm_state: RwLock<evm_state::EvmState>,
    pub(crate) evm_changed_list: RwLock<ChangedList>,
    pub(crate) evm_blockhashes: RwLock<BlockHashEvm>,
}

impl Clone for EvmChain {
    fn clone(&self) -> Self {
        Self {
            chain_id: self.chain_id.clone(),
            evm_state: RwLock::new(self.evm_state.read().unwrap().clone()),
            evm_changed_list: RwLock::new(self.evm_changed_list.read().unwrap().clone()),
            evm_blockhashes: RwLock::new(self.evm_blockhashes.read().unwrap().clone()),
        }
    }
}

impl EvmChain {
    /// EVM Chain ID
    pub fn id(&self) -> ChainID {
        self.chain_id
    }

    pub fn set_id(&mut self, id: ChainID) {
        self.chain_id = id;
    }

    /// EVM State Read-Only Lock Guard
    pub fn state<'a>(&'a self) -> std::sync::RwLockReadGuard<'a, evm_state::EvmState> {
        self.evm_state
            .read()
            .expect("EVM State RwLock was poisoned")
    }

    /// EVM State Write Lock Guard
    pub fn state_write<'a>(&'a self) -> std::sync::RwLockWriteGuard<'a, evm_state::EvmState> {
        self.evm_state
            .write()
            .expect("EVM State RwLock was poisoned")
    }

    /// EVM Blockhashes Raw Lock
    pub fn blockhashes_raw<'a>(&'a self) -> &'a RwLock<BlockHashEvm> {
        &self.evm_blockhashes
    }

    /// EVM Blockhashes Read-Only Lock Guard
    pub fn blockhashes<'a>(&'a self) -> std::sync::RwLockReadGuard<'a, BlockHashEvm> {
        self.evm_blockhashes
            .read()
            .expect("EVM Blockhashes RwLock was poisoned")
    }

    // TODO: do not expose WriteGuard, do setter
    /// EVM Blockhashes Write Lock Guard
    pub fn blockhashes_write<'a>(&'a self) -> std::sync::RwLockWriteGuard<'a, BlockHashEvm> {
        self.evm_blockhashes
            .write()
            .expect("EVM Blockhashes RwLock was poisoned")
    }

    /// EVM Blockhashes Read-Only Lock Guard
    pub fn changed_list<'a>(&'a self) -> std::sync::RwLockReadGuard<'a, ChangedList> {
        self.evm_changed_list
            .read()
            .expect("EVM Blockhashes RwLock was poisoned")
    }

    // TODO: do not expose WriteGuard, do setter
    /// EVM Blockhashes Write Lock Guard
    pub fn changed_list_write<'a>(&'a self) -> std::sync::RwLockWriteGuard<'a, ChangedList> {
        self.evm_changed_list
            .write()
            .expect("EVM Blockhashes RwLock was poisoned")
    }
}

#[derive(Debug, Default, PartialEq, Clone)]
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

    pub fn main_chain_mut(&mut self) -> &mut EvmChain {
        &mut self.main_chain
    }
}

impl PartialEq for EvmChain {
    fn eq(&self, other: &Self) -> bool {
        let last_root_self = self.state().last_root();
        let last_root_other = other.state().last_root();

        self.chain_id == other.chain_id && last_root_self == last_root_other
    }
}

// struct ExecutorContext {
//    ...
// };
// impl ExecutorContext {
//     pub fn get_executor(&mut self, chain_id: ChainID) -> Option<Executor>;
//     pub fn destruct(self) -> Vec<(ChainId, EvmBackend)>;
// }

// deserilalizer: fn (Account) -> ChainId;
// executor_factory: fn (ChainId) -> Option<Executor>;
// executor_getter: fn (Account) -> Option<Executor> = deserializer * executor_factory

type EvmPatch = evm_state::EvmBackend<evm_state::Incomming>;

pub enum EvmExecutorContextType {
    Execution,
    Simulation,
}

pub enum PatchStrategy {
    ApplyFailed,
    SetNew,
}

//
// 1. Init state: in solana::Bank::evm -> EvmExecutorContext::new()
// 2. State for tx_batch = evm_patch::new(init_state)
// 3. intermediate state for one tx = evm_executor::new(evm_patch)
pub struct EvmExecutorContext {
    evm: EvmBank,

    // TODO: evm_patches: HashMap<ChainID, EvmPatch>,
    evm_patch: Option<EvmPatch>,

    active_executor: Option<Rc<RefCell<Executor>>>,

    // extract into struct
    feature_set: evm_state::executor::FeatureSet,
    unix_timestamp: i64,
    bank_slot: Slot,

    // bank data used for logging
    is_bank_frozen: bool,
    is_evm_burn_fee_activated: bool,

    // used for cleanup
    // TODO: hardcode this flag to `true`
    pub evm_new_error_handling: bool,
    clear_logs: bool,

    // defines default state getter
    context_type: EvmExecutorContextType,
}

pub type RefCellLocked = ();

impl EvmExecutorContext {
    pub fn new(
        // TODO: EvmBank should be shared with solana::Bank
        evm: EvmBank,
        feature_set: evm_state::executor::FeatureSet,
        // NOTE: available from InvokeContext
        unix_timestamp: i64,
        bank_slot: Slot,
        is_bank_frozen: bool,
        is_evm_burn_fee_activated: bool,
        evm_new_error_handling: bool,
        clear_logs: bool,
        context_type: EvmExecutorContextType,
    ) -> Self {
        Self {
            evm,
            evm_patch: None,
            feature_set,
            unix_timestamp,
            bank_slot,
            is_bank_frozen,
            is_evm_burn_fee_activated,
            evm_new_error_handling,
            clear_logs,
            context_type,
            active_executor: None,
        }
    }

    pub fn get_executor(&mut self /* chain_id */) -> Option<Rc<RefCell<Executor>>> {
        // if self.active_executor.is_some() {
        //     warn!("not a warn: getting active executor");
        //     return self.active_executor.clone();
        // }

        // append to old patch if exist, or create new, from existing evm state
        // TODO: Can be inlined?
        self.evm_patch = self.evm_patch.take().or_else(|| match self.context_type {
            EvmExecutorContextType::Execution => self.take_evm_state_cloned(),
            EvmExecutorContextType::Simulation => self.take_evm_state_for_simulation(),
        });

        if let Some(state) = &self.evm_patch {
            let evm_executor = evm_state::Executor::with_config(
                state.clone(),
                evm_state::ChainContext::new(
                    self.evm.main_chain().blockhashes().get_hashes().clone(), // NOTE: 8kb
                ),
                evm_state::EvmConfig::new(
                    self.evm.main_chain().id(),
                    self.is_evm_burn_fee_activated,
                ),
                self.feature_set,
            );

            let evm_executor = Some(Rc::new(RefCell::new(evm_executor)));
            self.active_executor = evm_executor.clone();

            evm_executor
        } else {
            warn!("Executing evm transaction on already locked bank, ignoring.");
            None
        }
    }

    // for test purposes
    pub fn take_executor(&mut self) -> Option<Executor> {
        self.active_executor
            .take()
            .and_then(|rc| Rc::try_unwrap(rc).ok().map(|i| i.into_inner()))
    }

    // TODO: On cleanup:
    // for (chain_id, changed_patches) in evm_factory.destruct() {
    // if matches!(process_result, Err(TransactionError::InstructionError(..))) {
    //     evm_patch
    //         .get_mut(chain_id)
    //         .expect("Evm patch should exist, on transaction execution.")
    //         .apply_failed_update(&changed_patches, clear_logs);
    // } else {
    //     *evm_patch.get_mut(chain_id).expect("Evm patch should exist, on transaction execution.") = Some(changed_patches);
    // }

    // TODO: Return Result<(), E>. Let caller decide how to unwrap.
    /// # Panics
    pub fn cleanup(&mut self, strategy: PatchStrategy) {
        let executor: Executor = {
            let executor = self
                .active_executor
                .take()
                .expect("Executor was not created, nothing to deconstruct");
            Rc::try_unwrap(executor)
                .map(|e| e.into_inner())
                .expect("Reference to Active Executor was not freed")
        };

        let new_patch = executor.deconstruct();
        // On error save only transaction and increase nonce.
        match strategy {
            PatchStrategy::ApplyFailed => {
                self.evm_patch
                    .as_mut()
                    .expect("Evm patch should exist, on transaction execution.")
                    .apply_failed_update(&new_patch, self.clear_logs);
            }
            PatchStrategy::SetNew => {
                self.evm_patch = Some(new_patch);
            }
        }
    }

    pub fn get_patch_cloned(&self) -> Option<EvmPatch> {
        self.evm_patch.clone()
    }

    fn take_evm_state_cloned(&self) -> Option<evm_state::EvmBackend<evm_state::Incomming>> {
        match &*self.evm.main_chain().state() {
            evm_state::EvmState::Incomming(i) => Some(i.clone()),
            evm_state::EvmState::Committed(_) => {
                warn!(
                    "Take evm after freeze, bank_slot={}, bank_is_freeze={}",
                    self.bank_slot, self.is_bank_frozen
                );
                // Return None, so this transaction will fail to execute,
                // this transaction will be marked as retriable after bank realise that PoH is reached it's max height.
                None
            }
        }
    }

    fn take_evm_state_for_simulation(&self) -> Option<evm_state::EvmBackend<evm_state::Incomming>> {
        match &*self.evm.main_chain().state() {
            evm_state::EvmState::Incomming(i) => Some(i.clone()),
            evm_state::EvmState::Committed(c) => {
                debug!(
                    "Creating cloned evm state for simulation, bank_slot={}, bank_is_freeze={}",
                    self.bank_slot, self.is_bank_frozen
                );
                Some(c.next_incomming(self.unix_timestamp as u64))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use evm_state::H256;

    use super::*;

    #[test]
    fn test_evm_blockhaheshes() {
        let mut blockhash_queue = BlockHashEvm::new();
        assert_eq!(
            blockhash_queue.get_hashes(),
            &[H256::zero(); MAX_EVM_BLOCKHASHES]
        );
        let hash1 = H256::repeat_byte(1);
        blockhash_queue.insert_hash(hash1);
        for hash in &blockhash_queue.get_hashes()[..MAX_EVM_BLOCKHASHES - 1] {
            assert_eq!(*hash, H256::zero())
        }
        assert_eq!(blockhash_queue.get_hashes()[MAX_EVM_BLOCKHASHES - 1], hash1);

        for i in 0..MAX_EVM_BLOCKHASHES {
            let hash1 = H256::repeat_byte(i as u8);
            blockhash_queue.insert_hash(hash1)
        }

        for (i, hash) in blockhash_queue.get_hashes()[..MAX_EVM_BLOCKHASHES]
            .iter()
            .enumerate()
        {
            let hash1 = H256::repeat_byte(i as u8);
            assert_eq!(*hash, hash1)
        }
    }
}
