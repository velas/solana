pub use evm::{
    backend::{Apply, ApplyBackend, Backend, Log},
    executor::StackExecutor,
    Config, Context, Handler, Transfer,
};
pub use evm::{ExitError, ExitFatal, ExitReason, ExitRevert, ExitSucceed};
pub use primitive_types::{H256, U256};
pub use secp256k1::rand;

pub mod layered_backend;
pub mod transactions;

pub use evm_backend::*;
pub use layered_backend::*;
pub use transactions::*;

mod evm_backend;
mod mb_value;
mod storage;
mod version_map;

use log::debug;
use std::fmt;

pub(crate) type Slot = u64; // TODO: re-use existing one from sdk package

pub trait FromKey {
    fn to_public_key(&self) -> secp256k1::PublicKey;
    fn to_address(&self) -> crate::Address;
}

impl FromKey for secp256k1::SecretKey {
    fn to_public_key(&self) -> secp256k1::PublicKey {
        secp256k1::PublicKey::from_secret_key(&secp256k1::SECP256K1, self)
    }
    fn to_address(&self) -> crate::Address {
        addr_from_public_key(&secp256k1::PublicKey::from_secret_key(
            &secp256k1::SECP256K1,
            self,
        ))
    }
}

pub struct Executor {
    evm: EvmBackend,
    config: Config,
    used_gas: usize,
}

impl fmt::Debug for Executor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Executor")
            .field("config", &self.config)
            .finish()
    }
}

impl Executor {
    pub fn with_config(
        state: EvmState,
        config: Config,
        gas_limit: usize,
        block_number: u64,
    ) -> Self {
        //TODO: Request info from solana blockchain for vicinity

        //         /// Gas price.
        // pub gas_price: U256,
        // /// Chain ID.
        // pub chain_id: U256,
        // /// Environmental block hashes.
        // pub block_hashes: Vec<H256>,
        // /// Environmental block number.
        // pub block_number: U256,
        // /// Environmental coinbase.
        // pub block_coinbase: H160,
        // /// Environmental block timestamp.
        // pub block_timestamp: U256,
        // /// Environmental block difficulty.
        // pub block_difficulty: U256,
        // /// Environmental block gas limit.
        // pub block_gas_limit: U256,
        let vicinity = MemoryVicinity {
            block_gas_limit: gas_limit.into(),
            block_number: block_number.into(),
            ..Default::default()
        };
        Executor {
            evm: EvmBackend::new_from_state(state, vicinity),
            config,
            used_gas: 0,
        }
    }

    pub fn transaction_execute(
        &mut self,
        evm_tx: Transaction,
    ) -> Result<(evm::ExitReason, Vec<u8>), secp256k1::Error> {
        let caller = evm_tx.caller()?;

        self.evm.tx_info.origin = caller;
        self.evm.tx_info.gas_price = evm_tx.gas_price;
        let gas_limit = self.evm.block_gas_limit().as_usize() - self.used_gas;
        let mut executor = StackExecutor::new(&self.evm, gas_limit, &self.config);
        let result = match evm_tx.action {
            TransactionAction::Call(addr) => {
                debug!(
                    "TransactionAction::Call caller  = {}, to = {}.",
                    caller, addr
                );
                executor.transact_call(
                    caller,
                    addr,
                    evm_tx.value,
                    evm_tx.input.clone(),
                    evm_tx.gas_limit.as_usize(),
                )
            }
            TransactionAction::Create => {
                let addr = evm_tx.address();
                debug!(
                    "TransactionAction::Create caller  = {}, to = {:?}.",
                    caller, addr
                );
                (
                    executor.transact_create(
                        caller,
                        evm_tx.value,
                        evm_tx.input.clone(),
                        evm_tx.gas_limit.as_usize(),
                    ),
                    vec![],
                )
            }
        };
        let used_gas = executor.used_gas();

        assert!(used_gas + self.used_gas <= self.evm.tx_info.block_gas_limit.as_usize());
        let (updates, logs) = executor.deconstruct();
        self.evm.apply(updates, logs, false);
        self.register_tx_receipt(evm_tx, used_gas.into(), result.clone());
        self.used_gas += used_gas;

        Ok(result)
    }

    /// Do lowlevel operation with executor, without storing transaction into logs.
    /// Usefull for testing and transfering tokens from evm to solana and back.
    pub fn with_executor<F, U>(&mut self, func: F) -> U
    where
        F: FnOnce(&mut StackExecutor<'_, '_, EvmBackend>) -> U,
    {
        let gas_limit = self.evm.block_gas_limit().as_usize() - self.used_gas;
        let mut executor = StackExecutor::new(&self.evm, gas_limit, &self.config);
        let result = func(&mut executor);
        let (updates, logs) = executor.deconstruct();
        self.evm.apply(updates, logs, false);
        result
    }

    pub fn get_tx_receipt_by_hash(&mut self, tx: H256) -> Option<TransactionReceipt> {
        self.evm.evm_state.get_tx_receipt_by_hash(tx)
    }

    // TODO: Handle duplicates, statuses.
    fn register_tx_receipt(
        &mut self,
        tx: transactions::Transaction,
        used_gas: U256,
        result: (evm::ExitReason, Vec<u8>),
    ) {
        let block_num = self.evm.tx_info.block_number.as_u64();
        let tx_hash = tx.signing_hash();

        debug!("Register tx in evm block={}, tx= {}", block_num, tx_hash);
        // TODO: replace by Entry-like api
        let mut hashes = self
            .evm
            .evm_state
            .get_txs_in_block(block_num)
            .unwrap_or_default();
        hashes.push(tx_hash);

        let index = hashes.len() as u64;
        self.evm.evm_state.txs_in_block.insert(block_num, hashes);

        let tx_receipt = TransactionReceipt::new(tx, used_gas, block_num, index, result);
        self.evm.evm_state.txs_receipts.insert(tx_hash, tx_receipt);
    }

    pub fn deconstruct(self) -> EvmState {
        self.evm.evm_state
    }
}

pub const HELLO_WORLD_CODE:&str = "608060405234801561001057600080fd5b5061011e806100206000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c8063942ae0a714602d575b600080fd5b603360ab565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101560715780820151818401526020810190506058565b50505050905090810190601f168015609d5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60606040518060400160405280600a81526020017f68656c6c6f576f726c640000000000000000000000000000000000000000000081525090509056fea2646970667358221220fa787b95ca91ffe90fdb780b8ee8cb11c474bc63cb8217112c88bc465f7ea7d364736f6c63430007020033";
pub const HELLO_WORLD_ABI: &str = "942ae0a7";
pub const HELLO_WORLD_RESULT:&str = "0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000a68656c6c6f576f726c6400000000000000000000000000000000000000000000";
pub const HELLO_WORLD_CODE_SAVED:&str = "6080604052348015600f57600080fd5b506004361060285760003560e01c8063942ae0a714602d575b600080fd5b603360ab565b6040518080602001828103825283818151815260200191508051906020019080838360005b8381101560715780820151818401526020810190506058565b50505050905090810190601f168015609d5780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60606040518060400160405280600a81526020017f68656c6c6f576f726c640000000000000000000000000000000000000000000081525090509056fea2646970667358221220fa787b95ca91ffe90fdb780b8ee8cb11c474bc63cb8217112c88bc465f7ea7d364736f6c63430007020033";

#[cfg(test)]
mod test_utils;

#[cfg(test)]
mod tests {
    use anyhow::anyhow;

    use evm::{Capture, CreateScheme, ExitReason, ExitSucceed, Handler};
    use primitive_types::{H160, H256, U256};
    use sha3::{Digest, Keccak256};

    use crate::test_utils::TmpDir;

    use super::Executor;
    use super::*;

    fn name_to_key(name: &str) -> H160 {
        let hash = H256::from_slice(Keccak256::digest(name.as_bytes()).as_slice());
        hash.into()
    }

    #[test]
    fn test_evm_bytecode() -> anyhow::Result<()> {
        simple_logger::SimpleLogger::new().init()?;
        let accounts = ["contract", "caller"];

        let code = hex::decode(HELLO_WORLD_CODE)?;
        let data = hex::decode(HELLO_WORLD_ABI)?;

        let tmp_dir = TmpDir::new("test_evm_bytecode");
        let mut backend = EvmState::load_from(tmp_dir, Slot::default())?;

        for acc in &accounts {
            let account = name_to_key(acc);
            let memory = AccountState {
                ..Default::default()
            };
            backend.accounts.insert(account, memory);
        }

        backend.freeze();

        let config = evm::Config::istanbul();
        let mut executor = Executor::with_config(
            backend
                .try_fork(backend.slot + 1)
                .ok_or_else(|| anyhow!("Unable to fork backend"))?,
            config,
            usize::max_value(),
            0,
        );

        let exit_reason = match executor.with_executor(|e| {
            e.create(
                name_to_key("caller"),
                CreateScheme::Fixed(name_to_key("contract")),
                U256::zero(),
                code,
                None,
            )
        }) {
            Capture::Exit((s, _, v)) => (s, v),
            Capture::Trap(_) => unreachable!(),
        };

        assert!(matches!(
            exit_reason,
            (ExitReason::Succeed(ExitSucceed::Returned), _)
        ));
        let exit_reason = executor.with_executor(|e| {
            e.transact_call(
                name_to_key("contract"),
                name_to_key("contract"),
                U256::zero(),
                data.to_vec(),
                300000,
            )
        });

        let result = hex::decode(HELLO_WORLD_RESULT)?;
        match exit_reason {
            (ExitReason::Succeed(ExitSucceed::Returned), res) if res == result => {}
            any_other => panic!("Not expected result={:?}", any_other),
        }

        let patch = executor.deconstruct();
        backend.swap_commit(patch);

        let contract = backend.get_account(name_to_key("contract"));
        assert_eq!(
            &contract.unwrap().code,
            &hex::decode(HELLO_WORLD_CODE_SAVED).unwrap()
        );
        Ok(())
    }
}
