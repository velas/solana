use {
    super::Bank,
    crate::{bank::log_enabled, message_processor::ProcessedMessageInfo},
    evm_state::{AccountProvider, FromKey},
    log::debug,
    solana_measure::measure::Measure,
    solana_program_runtime::evm_executor_context::{
        BlockHashEvm, Chain, EvmBank, EvmExecutorContext, EvmExecutorContextType, PatchStrategy,
        MAX_EVM_BLOCKHASHES,
    },
    solana_sdk::{
        feature_set,
        hash::Hash,
        recent_evm_blockhashes_account,
        signature::{Keypair, Signature},
        signer::Signer,
        sysvar,
        transaction::{Result, Transaction, TransactionError},
    },
};

impl Bank {
    pub fn evm(&self) -> &EvmBank {
        &self.evm
    }

    pub fn evm_blocks(&self) -> Vec<(Chain, evm_state::Block)> {
        self.evm
            .main_chain()
            .state()
            .get_block()
            .map(|block| (None, block))
            .into_iter()
            .chain(
                self.evm
                    .side_chains()
                    .iter()
                    .filter_map(|s| s.value().evm_state.get_block().map(|b| (Some(*s.key()), b))),
            )
            .collect()
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

        let last_blockhash = self.last_blockhash().to_bytes();
        let hash = self
            .evm
            .main_chain()
            .state_write()
            .try_commit(self.slot(), last_blockhash)
            .expect("failed to commit evm");

        // TODO: cleanup default?
        for mut chain in self.evm.side_chains().iter_mut() {
            let subchain_old_root = chain.evm_state.last_root();
            let Some((_block_hash, changes)) = chain
                .value_mut()
                .evm_state
                //TODO: apply block_hash on subchain
                .try_commit(self.slot(), last_blockhash)
                .expect("failed to commit evm")
            else {
                // nothing to do
                continue;
            };
            chain.evm_changed_list = Some((subchain_old_root, changes));
        }

        measure.stop();
        debug!("EVM state commit took {}", measure);

        inc_new_counter_info!("commit-evm-block-ms", measure.as_ms() as usize);

        debug!(
            "Set evm state root to {:?} at block {}",
            self.evm.main_chain().state().last_root(),
            self.evm.main_chain().state().block_number()
        );

        if let Some((hash, changes)) = hash {
            let mut w_evm_blockhash_queue = self.evm.main_chain().blockhashes_write();
            *self.evm.main_chain().changed_list_write() = Some((old_root, changes));

            let subchain_roots = self.evm.subchain_roots();

            // TODO: feature_subchain
            self.evm
                .main_chain()
                .state_write()
                .reregister_slot(self.slot(), subchain_roots)
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

pub fn debug_evm_roots(
    storage: evm_state::Storage,
    main: evm_state::H256,
    subchain_roots: &[evm_state::H256],
) {
    log::warn!(
        "EVM_root_count: main {} = {}",
        main,
        storage.gc_count(main).unwrap()
    );

    for subchain_root in subchain_roots {
        log::warn!(
            "EVM_root_count: Subchain {subchain_root} = {}",
            storage.gc_count(*subchain_root).unwrap()
        );
    }
}

#[cfg(test)]
mod evmtests {

    pub use solana_sdk::reward_type::RewardType;
    use {
        crate::bank::Bank,
        evm_state::{AccountProvider, EvmState, FromKey, H160, TEST_CHAIN_ID, U256},
        log::*,
        solana_evm_loader_program::{
            precompiles::ETH_TO_VLX_ADDR,
            processor::SUBCHAIN_CREATION_DEPOSIT_VLX,
            scope::evm::{gweis_to_lamports, lamports_to_gwei},
        },
        solana_program_runtime::{evm_executor_context::StateExt, timings::ExecuteTimings},
        solana_sdk::{
            account::ReadableAccount,
            clock::MAX_PROCESSING_AGE,
            feature_set,
            hash::Hash,
            native_token::LAMPORTS_PER_VLX,
            pubkey::Pubkey,
            transaction::{Transaction, TransactionError},
        },
        std::sync::Arc,
    };
    #[allow(deprecated)]
    use {
        evm_state::H256,
        solana_program_runtime::invoke_context::InvokeContext,
        solana_sdk::{
            genesis_config::create_genesis_config,
            instruction::InstructionError,
            message::Message,
            signature::{Keypair, Signer},
        },
        std::time::Duration,
    };

    #[test]
    fn test_interleaving_locks_evm_tx() {
        solana_logger::setup_with("trace");

        let (genesis_config, mint_keypair) = create_genesis_config(20000 * 3);
        let mut bank = Bank::new_for_tests(&genesis_config);
        let alice = Keypair::new();
        let bob = Keypair::new();

        bank.activate_feature(&feature_set::velas::evm_instruction_borsh_serialization::id());
        fn fund_evm(from_keypair: &Keypair, hash: Hash, lamports: u64) -> Transaction {
            let tx = solana_evm_loader_program::processor::dummy_call(0).0;
            let from_pubkey = from_keypair.pubkey();
            let instructions = solana_evm_loader_program::transfer_native_to_evm_ixs(
                from_pubkey,
                lamports,
                tx.caller().unwrap(),
            );
            let message = Message::new(&instructions, Some(&from_pubkey));
            Transaction::new(&[from_keypair], message, hash)
        }

        let recent_hash = genesis_config.hash();
        assert!(bank.transfer(20000, &mint_keypair, &alice.pubkey()).is_ok());
        let tx = fund_evm(&mint_keypair, recent_hash, 20000);
        bank.process_transaction(&tx).unwrap();
        assert!(bank.transfer(20000, &mint_keypair, &bob.pubkey()).is_ok());

        let create_tx = |from_keypair: &Keypair, hash: Hash, nonce: usize| {
            let from_pubkey = from_keypair.pubkey();
            let instruction = solana_evm_loader_program::send_raw_tx(
                from_pubkey,
                solana_evm_loader_program::processor::dummy_call(nonce).0,
                None,
                solana_evm_loader_program::instructions::FeePayerType::Evm,
            );
            let message = Message::new(&[instruction], Some(&from_pubkey));
            Transaction::new(&[from_keypair], message, hash)
        };

        let tx1 = create_tx(&alice, genesis_config.hash(), 0);
        let first_call = vec![tx1];

        let lock_result = bank.prepare_batch_for_tests(first_call);
        let results_alice = bank
            .load_execute_and_commit_transactions(
                &lock_result,
                MAX_PROCESSING_AGE,
                false,
                false,
                false,
                &mut ExecuteTimings::default(),
            )
            .0
            .fee_collection_results;
        assert_eq!(results_alice[0], Ok(()));

        // try executing an evm transaction from other key, but while lock is active
        let blockhash = bank.last_blockhash();
        let tx = create_tx(&bob, blockhash, 1);
        assert_eq!(
            bank.process_transaction(&tx),
            Err(TransactionError::AccountInUse)
        );

        // the second time should fail as well
        // this verifies that `unlock_accounts` doesn't unlock `AccountInUse` accounts
        let blockhash = bank.last_blockhash();
        let tx = create_tx(&bob, blockhash, 1);
        assert_eq!(
            bank.process_transaction(&tx),
            Err(TransactionError::AccountInUse)
        );

        drop(lock_result);

        let blockhash = bank.last_blockhash();
        let tx = create_tx(&bob, blockhash, 1);

        bank.process_transaction(&tx).unwrap();
    }

    /// Process two batches, one with some slow routine, and second with evm state modification.
    /// Both batches are without conflicts, expect that with any size of sleep, evm batch will modify state root.
    #[test]
    fn test_evm_really_change_state_in_parallel() {
        solana_logger::setup();
        fn create_evm_tx(from_keypair: &Keypair, hash: Hash, nonce: usize) -> Transaction {
            let from_pubkey = from_keypair.pubkey();
            let instruction = solana_evm_loader_program::send_raw_tx(
                from_pubkey,
                solana_evm_loader_program::processor::dummy_call(nonce).0,
                None,
                solana_evm_loader_program::instructions::FeePayerType::Evm,
            );
            let message = Message::new(&[instruction], Some(&from_pubkey));
            Transaction::new(&[from_keypair], message, hash)
        }

        fn fund_evm(from_keypair: &Keypair, hash: Hash, lamports: u64) -> Transaction {
            let tx = solana_evm_loader_program::processor::dummy_call(0).0;
            let from_pubkey = from_keypair.pubkey();
            let instructions = solana_evm_loader_program::transfer_native_to_evm_ixs(
                from_pubkey,
                lamports,
                tx.caller().unwrap(),
            );
            let message = Message::new(&instructions, Some(&from_pubkey));
            Transaction::new(&[from_keypair], message, hash)
        }

        fn create_sleep_tx(
            sleep_program_id: &Pubkey,
            user: &Keypair,
            recent_hash: Hash,
            sleep: u32,
        ) -> Transaction {
            let instruction = crate::loader_utils::create_invoke_instruction(
                user.pubkey(),
                *sleep_program_id,
                &sleep,
            );
            let message = Message::new(&[instruction], Some(&user.pubkey()));
            Transaction::new(&[user], message, recent_hash)
        }
        // returns evm hash before and after apply
        fn test_with_users(num_sleeps: u64) -> (evm_state::H256, evm_state::H256) {
            fn process_sleep_instruction(
                _first_instruction_account: usize,
                data: &[u8],
                _invoke_context: &mut InvokeContext,
            ) -> std::result::Result<(), InstructionError> {
                const MAX_SLEEP_MS: u32 = 1000;
                if data.len() != 4 {
                    error!("data len should be 4 bytes");
                    return Err(InstructionError::InvalidInstructionData);
                }
                let mut data_arr = [0; 4];
                data_arr.copy_from_slice(&data);
                let ms = u32::from_be_bytes(data_arr);

                let sleep_ms = ms % MAX_SLEEP_MS;
                trace!("Sleep: sleeping ms {}", sleep_ms);
                std::thread::sleep(Duration::from_millis(sleep_ms.into()));
                Ok(())
            }

            let (genesis_config, mint_keypair) = create_genesis_config(20000 * (num_sleeps + 3));
            let mut bank = Bank::new_for_tests(&genesis_config);

            bank.activate_feature(&feature_set::velas::evm_instruction_borsh_serialization::id());
            let sleep_program_id = solana_sdk::pubkey::new_rand();
            bank.add_builtin(
                "solana_sleep_program",
                &sleep_program_id,
                process_sleep_instruction,
            );

            let recent_hash = genesis_config.hash();

            let alice = Keypair::new();
            assert!(bank.transfer(20000, &mint_keypair, &alice.pubkey()).is_ok());

            let tx = fund_evm(&mint_keypair, recent_hash, 20000);
            bank.process_transaction(&tx).unwrap();
            let mut users = Vec::new();
            users.resize_with(num_sleeps as usize, Keypair::new);
            for user in &users {
                assert!(bank.transfer(20000, &mint_keypair, &user.pubkey()).is_ok());
            }

            let tx1 = create_evm_tx(&alice, recent_hash, 0);
            let fast_batch = vec![tx1];

            let mut slow_batch = vec![];
            for user in &users {
                // Call user program
                slow_batch.push(create_sleep_tx(&sleep_program_id, user, recent_hash, 10))
            }

            // execute two batches parallel, with replacement
            rayon::scope(|s| {
                s.spawn(|_| {
                    bank.process_transactions(slow_batch.iter())
                        .into_iter()
                        .map(|i| i.unwrap())
                        .collect()
                });
                s.spawn(|_| {
                    bank.process_transactions(fast_batch.iter())
                        .into_iter()
                        .map(|i| i.unwrap())
                        .collect()
                });
            });

            let hash_before = bank.evm.main_chain().state().last_root();
            bank.freeze();
            let hash_after = bank.evm.main_chain().state().last_root();
            (hash_before, hash_after)
        }

        for i in &[0, 1, 2, 5, 10, 20, 100] {
            info!("Testing evm consistency with {} sleep txs after evm", i);
            let (before, after) = test_with_users(*i);
            assert_ne!(before, after);
        }
    }

    /// Test that only processed transaction should increase nonce.
    /// Transaction that has invalid txid/nonce/fee should not be processed.
    #[test]
    fn test_evm_second_tx_with_same_nonce() {
        solana_logger::setup_with("trace");
        fn fund_evm(from_keypair: &Keypair, hash: Hash, lamports: u64) -> Transaction {
            let tx = solana_evm_loader_program::processor::dummy_call(0).0;
            let from_pubkey = from_keypair.pubkey();
            let instructions = solana_evm_loader_program::transfer_native_to_evm_ixs(
                from_pubkey,
                lamports,
                tx.caller().unwrap(),
            );
            let message = Message::new(&instructions, Some(&from_pubkey));
            Transaction::new(&[from_keypair], message, hash)
        }
        fn evm_call(from_keypair: &Keypair, hash: Hash, nonce: usize) -> Transaction {
            let from_pubkey = from_keypair.pubkey();

            let instruction = solana_evm_loader_program::send_raw_tx(
                from_pubkey,
                solana_evm_loader_program::processor::dummy_call(nonce).0,
                None,
                solana_evm_loader_program::instructions::FeePayerType::Evm,
            );

            let message = Message::new(&[instruction], Some(&from_pubkey));
            Transaction::new(&[from_keypair], message, hash)
        }
        let tx = solana_evm_loader_program::processor::dummy_call(0).0;
        let receiver = tx.caller().unwrap();
        let (genesis_config, mint_keypair) = create_genesis_config(40000);
        let mut bank = Bank::new_for_tests(&genesis_config);

        bank.activate_feature(&feature_set::velas::native_swap_in_evm_history::id());
        bank.activate_feature(&feature_set::velas::evm_new_error_handling::id());
        bank.activate_feature(&feature_set::velas::evm_instruction_borsh_serialization::id());
        let recent_hash = genesis_config.hash();

        let tx = fund_evm(&mint_keypair, recent_hash, 20000);
        let _res = bank.process_transaction(&tx).unwrap();

        bank.freeze();

        let bank = Arc::new(bank);
        let bank = Bank::new_from_parent(&bank, &Pubkey::default(), 1);

        let state = bank
            .evm
            .main_chain()
            .state()
            .get_account_state(receiver)
            .unwrap_or_default();
        assert_eq!(state.nonce, 0.into());

        let tx = evm_call(&mint_keypair, recent_hash, 0);
        let _res = bank.process_transaction(&tx).unwrap();

        let hash_before = bank.evm.main_chain().state().last_root();
        bank.freeze();
        let hash_after = bank.evm.main_chain().state().last_root();

        assert_ne!(hash_before, hash_after); // nonce increased in old version

        let state = bank
            .evm
            .main_chain()
            .state()
            .get_account_state(receiver)
            .unwrap_or_default();
        assert_eq!(state.nonce, 1.into());

        assert_eq!(bank.evm.main_chain().state().processed_tx_len(), 1);

        // Second try same tx
        let bank = Arc::new(bank);
        let bank = Bank::new_from_parent(&bank, &Pubkey::default(), 2);

        let state = bank
            .evm
            .main_chain()
            .state()
            .get_account_state(receiver)
            .unwrap_or_default();
        assert_eq!(state.nonce, 1.into());
        let tx = evm_call(&mint_keypair, recent_hash, 0); // send tx with same nonce
        let _res = bank.process_transaction(&tx).unwrap_err(); // execution should fail

        let hash_before = bank.evm.main_chain().state().last_root();
        bank.freeze();
        let hash_after = bank.evm.main_chain().state().last_root();

        assert_eq!(hash_before, hash_after); // nonce increased in old version

        assert_eq!(bank.evm.main_chain().state().processed_tx_len(), 0);

        let state = bank
            .evm
            .main_chain()
            .state()
            .get_account_state(receiver)
            .unwrap_or_default();
        assert_eq!(state.nonce, 1.into());
    }

    #[test]
    fn test_evm_revert_tx() {
        solana_logger::setup_with("trace");
        fn fund_evm_with_revert(
            from_keypair: &Keypair,
            receiver: evm_state::H160,
            hash: Hash,
            lamports: u64,
        ) -> Transaction {
            let from_pubkey = from_keypair.pubkey();
            let mut instructions = solana_evm_loader_program::transfer_native_to_evm_ixs(
                from_pubkey,
                lamports,
                receiver,
            );
            let s = Keypair::new();
            // add invalid ix that should revert tx
            let ix = solana_evm_loader_program::free_ownership(s.pubkey());
            instructions.push(ix);
            let message = Message::new(&instructions, Some(&from_pubkey));
            Transaction::new(&[from_keypair, &s], message, hash)
        }
        let tx = solana_evm_loader_program::processor::dummy_call(0).0;
        let receiver = tx.caller().unwrap();
        let (genesis_config, mint_keypair) = create_genesis_config(20000);
        let mut bank = Bank::new_for_tests(&genesis_config);

        bank.activate_feature(&feature_set::velas::native_swap_in_evm_history::id());
        bank.activate_feature(&feature_set::velas::evm_new_error_handling::id());
        bank.activate_feature(&feature_set::velas::evm_instruction_borsh_serialization::id());
        let recent_hash = genesis_config.hash();

        let tx = fund_evm_with_revert(&mint_keypair, receiver, recent_hash, 20000);
        let res = bank.process_transaction(&tx);

        res.unwrap_err();

        let hash_before = bank.evm.main_chain().state().last_root();
        bank.freeze();

        let evm_state = bank.evm.main_chain().state();
        let hash_after = evm_state.last_root();

        // check that revert keep tx in history, but balances are set to zero
        assert_eq!(evm_state.processed_tx_len(), 1);
        let account = bank.get_account(&mint_keypair.pubkey()).unwrap();
        assert_eq!(account.lamports(), 20000);
        let state = evm_state.get_account_state(receiver).unwrap_or_default();
        assert_eq!(state.balance, 0.into());
        let state_swapper = evm_state
            .get_account_state(*solana_evm_loader_program::precompiles::ETH_TO_VLX_ADDR)
            .unwrap_or_default();
        assert_eq!(state_swapper.nonce, 1.into());
        assert_eq!(state_swapper.balance, 0.into());

        // hash updated with nonce increasing
        assert_ne!(hash_before, hash_after);
    }

    #[test]
    fn test_evm_revert_tx_swap() {
        solana_logger::setup_with("trace");
        fn fund_evm_with_evm_call(
            from_keypair: &Keypair,
            receiver: evm_state::H160,
            hash: Hash,
            lamports: u64,
            nonce: usize,
        ) -> Transaction {
            let from_pubkey = from_keypair.pubkey();
            let mut instructions = solana_evm_loader_program::transfer_native_to_evm_ixs(
                from_pubkey,
                lamports,
                receiver,
            );
            let instruction = solana_evm_loader_program::send_raw_tx(
                from_pubkey,
                solana_evm_loader_program::processor::dummy_call(nonce).0,
                None,
                solana_evm_loader_program::instructions::FeePayerType::Evm,
            );
            instructions.push(instruction);
            let s = Keypair::new();
            // add invalid ix that should revert tx
            let ix = solana_evm_loader_program::free_ownership(s.pubkey());
            instructions.push(ix);
            let message = Message::new(&instructions, Some(&from_pubkey));
            Transaction::new(&[from_keypair, &s], message, hash)
        }
        let tx = solana_evm_loader_program::processor::dummy_call(0).0;
        let receiver = tx.caller().unwrap();
        let (genesis_config, mint_keypair) = create_genesis_config(20000);
        let mut bank = Bank::new_for_tests(&genesis_config);

        bank.activate_feature(&feature_set::velas::native_swap_in_evm_history::id());
        bank.activate_feature(&feature_set::velas::evm_new_error_handling::id());
        bank.activate_feature(&feature_set::velas::evm_instruction_borsh_serialization::id());
        let recent_hash = genesis_config.hash();

        let tx = fund_evm_with_evm_call(&mint_keypair, receiver, recent_hash, 20000, 0);
        let res = bank.process_transaction(&tx);

        res.unwrap_err();

        let hash_before = bank.evm().main_chain().state().last_root();
        bank.freeze();

        let evm_state = bank.evm().main_chain().state();
        let hash_after = evm_state.last_root();

        // check that revert keep tx in history, but balances are set to zero
        assert_eq!(evm_state.processed_tx_len(), 2);
        let account = bank.get_account(&mint_keypair.pubkey()).unwrap();
        assert_eq!(account.lamports(), 20000);
        let state = evm_state.get_account_state(receiver).unwrap_or_default();
        assert_eq!(state.balance, 0.into());
        assert_eq!(state.nonce, 1.into());
        let state_swapper = evm_state
            .get_account_state(*solana_evm_loader_program::precompiles::ETH_TO_VLX_ADDR)
            .unwrap_or_default();
        assert_eq!(state_swapper.nonce, 1.into());
        assert_eq!(state_swapper.balance, 0.into());

        // hash updated with nonce increasing
        assert_ne!(hash_before, hash_after);
    }

    #[test]
    fn test_evm_no_revert_tx_on_new_errorhandling() {
        solana_logger::setup();
        fn fund_evm(
            from_keypair: &Keypair,
            receiver: evm_state::H160,
            hash: Hash,
            lamports: u64,
        ) -> Transaction {
            let from_pubkey = from_keypair.pubkey();
            let instructions = solana_evm_loader_program::transfer_native_to_evm_ixs(
                from_pubkey,
                lamports,
                receiver,
            );
            let message = Message::new(&instructions, Some(&from_pubkey));
            Transaction::new(&[from_keypair], message, hash)
        }
        let tx = solana_evm_loader_program::processor::dummy_call(0).0;
        let receiver = tx.caller().unwrap();
        let (genesis_config, mint_keypair) = create_genesis_config(20000);
        let mut bank = Bank::new_for_tests(&genesis_config);

        bank.activate_feature(&feature_set::velas::native_swap_in_evm_history::id());
        bank.activate_feature(&feature_set::velas::evm_new_error_handling::id());
        bank.activate_feature(&feature_set::velas::evm_instruction_borsh_serialization::id());
        let recent_hash = genesis_config.hash();

        let tx = fund_evm(&mint_keypair, receiver, recent_hash, 20000);
        let res = bank.process_transaction(&tx);

        res.unwrap();

        let hash_before = bank.evm.main_chain().state().last_root();
        bank.freeze();

        let evm_state = bank.evm.main_chain().state();
        let hash_after = evm_state.last_root();

        // check that revert keep tx in history, but balances are set to zero
        assert_eq!(evm_state.processed_tx_len(), 1);
        let account = bank.get_account(&mint_keypair.pubkey()).unwrap_or_default();
        assert_eq!(account.lamports(), 0);
        let state = evm_state.get_account_state(receiver).unwrap_or_default();
        assert_eq!(
            state.balance,
            solana_evm_loader_program::scope::evm::lamports_to_gwei(20000)
        ); // 10^9 times bigger
        let state_swapper = evm_state
            .get_account_state(*solana_evm_loader_program::precompiles::ETH_TO_VLX_ADDR)
            .unwrap_or_default();
        assert_eq!(state_swapper.nonce, 1.into());
        assert_eq!(state_swapper.balance, 0.into());

        assert_ne!(hash_before, hash_after);
    }

    #[test]
    fn test_bank_hash_internal_state_verify_transfer_evm() {
        solana_logger::setup_with("trace");
        let (genesis_config, mint_keypair) = create_genesis_config(2_000);
        let mut bank0 = Bank::new_for_tests(&genesis_config);

        bank0.activate_feature(&feature_set::velas::evm_instruction_borsh_serialization::id());
        let mut rng = evm_state::rand::thread_rng();
        let sender = evm_state::SecretKey::new(&mut rng);
        let sender_addr = sender.to_address();
        let init_balance = 10000000.into();
        {
            // force changing evm_state account
            let mut evm_state = bank0.evm.main_chain().state_write();
            match &mut *evm_state {
                evm_state::EvmState::Incomming(i) => {
                    i.set_initial(vec![(
                        sender_addr,
                        evm_state::MemoryAccount {
                            balance: init_balance,
                            ..Default::default()
                        },
                    )]);
                }
                _ => panic!("Not exepcetd state"),
            }

            evm_state
                .try_commit(bank0.slot(), bank0.last_blockhash().to_bytes())
                .unwrap();
        }
        let pubkey: evm_state::H160 = H256::random().into();
        {
            let evm_state = bank0.evm.main_chain().state();
            assert_eq!(
                evm_state.get_account_state(sender_addr).unwrap().balance,
                init_balance
            );
        }
        info!("transfer 1 {} mint: {}", pubkey, mint_keypair.pubkey());
        bank0
            .transfer_evm(1_000, &mint_keypair, &sender, &pubkey)
            .unwrap();

        let bank0_state = bank0.hash_internal_state();
        let bank0 = Arc::new(bank0);

        // Checkpointing should result in a new state while freezing the parent
        let bank2 = Bank::new_from_parent(&bank0, &solana_sdk::pubkey::new_rand(), 1);

        {
            let evm_state = bank2.evm.main_chain().state();
            assert_eq!(
                evm_state.get_account_state(sender_addr).unwrap().balance,
                init_balance - 21000 - 1000
            );
        }
        assert_ne!(bank0_state, bank2.hash_internal_state());
        // Checkpointing should modify the checkpoint's state when freezed
        assert_ne!(bank0_state, bank0.hash_internal_state());

        // Checkpointing should never modify the checkpoint's state once frozen
        let bank0_state = bank0.hash_internal_state();
        bank2.update_accounts_hash();
        assert!(bank2.verify_bank_hash(true, false));
        let bank3 = Bank::new_from_parent(&bank0, &solana_sdk::pubkey::new_rand(), 2);
        assert_eq!(bank0_state, bank0.hash_internal_state());
        assert!(bank2.verify_bank_hash(true, false));
        bank3.update_accounts_hash();
        assert!(bank3.verify_bank_hash(true, false));

        let pubkey2: evm_state::H160 = H256::random().into();
        info!("failed transfer 2(insufficient funds) {}", pubkey2);
        bank2
            .transfer_evm(10000000, &mint_keypair, &sender, &pubkey2)
            .unwrap_err();
        bank2.update_accounts_hash();
        assert!(bank2.verify_bank_hash(true, false));
        assert!(bank3.verify_bank_hash(true, false));
        drop(bank0);
        drop(bank2);
        let evm_state = bank3.evm.main_chain().state();
        assert_eq!(
            evm_state.get_account_state(sender_addr).unwrap().balance,
            init_balance - 21000 - 1000
        );
    }

    #[test]
    fn test_bank_transfer_evm_release_lock_panic() {
        solana_logger::setup_with("trace");
        let (genesis_config, mint_keypair) = create_genesis_config(2_000);
        let mut bank0 = Bank::new_for_tests(&genesis_config);

        bank0.activate_feature(&feature_set::velas::evm_instruction_borsh_serialization::id());
        let mut rng = evm_state::rand::thread_rng();
        let sender = evm_state::SecretKey::new(&mut rng);
        let sender_addr = sender.to_address();
        let init_balance = 10000000.into();
        {
            // force changing evm_state account
            let mut evm_state = bank0.evm.main_chain().state_write();
            match &mut *evm_state {
                evm_state::EvmState::Incomming(i) => {
                    i.set_initial(vec![(
                        sender_addr,
                        evm_state::MemoryAccount {
                            balance: init_balance,
                            ..Default::default()
                        },
                    )]);
                }
                _ => panic!("Not exepcetd state"),
            }

            evm_state
                .try_commit(bank0.slot(), bank0.last_blockhash().to_bytes())
                .unwrap();
        }
        let pubkey: evm_state::H160 = H256::random().into();
        {
            let evm_state = bank0.evm.main_chain().state();
            assert_eq!(
                evm_state.get_account_state(sender_addr).unwrap().balance,
                init_balance
            );
        }
        info!("transfer 1 {} mint: {}", pubkey, mint_keypair.pubkey());
        bank0
            .transfer_evm(1_000, &mint_keypair, &sender, &pubkey)
            .unwrap();
        let bank0 = Arc::new(bank0);

        // Checkpointing should result in a new state while freezing the parent
        let bank2 = Bank::new_from_parent(&bank0, &solana_sdk::pubkey::new_rand(), 1);

        drop(bank0);
        {
            let evm_state = bank2.evm.main_chain().state();
            assert_eq!(
                evm_state.get_account_state(sender_addr).unwrap().balance,
                init_balance - 21000 - 1000
            );
        }
        let evm_state = bank2.evm.main_chain().state().clone();
        {
            assert_eq!(
                evm_state.get_account_state(sender_addr).unwrap().balance,
                init_balance - 21000 - 1000
            );
        }
        drop(bank2);

        std::panic::catch_unwind(|| evm_state.get_account_state(sender_addr)).unwrap_err();
    }

    fn create_subchain_with_preseed(
        from_keypair: &Keypair,
        receiver: evm_state::H160,
        chain_id: u64,
        hash: Hash,
        lamports: u64,
    ) -> Transaction {
        let mut config: solana_evm_loader_program::instructions::SubchainConfig =
            Default::default();
        config.mint.push((receiver, lamports.into()));
        let from_pubkey = from_keypair.pubkey();
        let instruction =
            solana_evm_loader_program::create_evm_subchain_account(from_pubkey, chain_id, config);
        let message = Message::new(&[instruction], Some(&from_pubkey));
        Transaction::new(&[from_keypair], message, hash)
    }

    #[test]
    fn create_evm_subchain_no_deposit() {
        solana_logger::setup_with("trace");

        let tx = solana_evm_loader_program::processor::dummy_call(0).0;
        let receiver = tx.caller().unwrap();
        let (genesis_config, mint_keypair) = create_genesis_config(20000); // no enough tokens for deposit
        let mut bank = Bank::new_for_tests(&genesis_config);

        bank.activate_feature(&feature_set::velas::native_swap_in_evm_history::id());
        bank.activate_feature(&feature_set::velas::evm_new_error_handling::id());
        bank.activate_feature(&feature_set::velas::evm_instruction_borsh_serialization::id());
        let recent_hash = genesis_config.hash();

        let hash_before = bank.evm.chain_state(TEST_CHAIN_ID + 1).state().last_root();
        let tx = create_subchain_with_preseed(
            &mint_keypair,
            receiver,
            TEST_CHAIN_ID + 1,
            recent_hash,
            20000,
        );
        let res = bank.process_transaction(&tx);

        let _err = res.unwrap_err();

        bank.freeze();

        let evm_state = bank.evm.main_chain().state();

        // check that revert keep tx in history, but balances are set to zero
        assert_eq!(evm_state.processed_tx_len(), 0);

        let subchain_evm_state = bank.evm.chain_state(TEST_CHAIN_ID + 1).state();

        // no deposit no tx
        assert_eq!(subchain_evm_state.processed_tx_len(), 0);
        let account = bank.get_account(&mint_keypair.pubkey()).unwrap();
        assert_eq!(account.lamports(), 20000);
        let state = subchain_evm_state
            .get_account_state(receiver)
            .unwrap_or_default();
        assert_eq!(state.balance, 0.into());

        let hash_after = bank.evm.chain_state(TEST_CHAIN_ID + 1).state().last_root();
        // hash updated with nonce increasing
        // state is not changed, but blockhash is changed.
        assert_eq!(hash_before, hash_after);
    }

    #[test]
    fn send_evm_subchain_tx() {
        // Add check that after creating, and sending tx subchain evm_state is changed but it last_root is not.
        todo!();
        // 1. create bank
        // get last_root of main and sub_chain
        // 2. create subchain account
        // 3. check_roots()  == 1
        // 4. bank.freeze() bank = bank.from_parent()
        // 5. check_roots()  != 3
        // 6. let prev = get_evm_state()
        // 7. send_subchain_tx()
        // 8. check_evm_state(prev)
        // 9. check_roots() == 5
        // 10. bank.freeze()
        // 11. check_roots() != 9
    }
    #[test]
    fn create_evm_subchain_regular() {
        solana_logger::setup_with("trace");
        let tx = solana_evm_loader_program::processor::dummy_call(0).0;
        let receiver = tx.caller().unwrap();
        let (genesis_config, mint_keypair) = create_genesis_config(LAMPORTS_PER_VLX * 1_000_001);
        let mut bank = Bank::new_for_tests(&genesis_config);

        bank.activate_feature(&feature_set::velas::native_swap_in_evm_history::id());
        bank.activate_feature(&feature_set::velas::evm_new_error_handling::id());
        bank.activate_feature(&feature_set::velas::evm_instruction_borsh_serialization::id());
        let bank = Arc::new(bank);
        let recent_hash = genesis_config.hash();

        let tx = create_subchain_with_preseed(
            &mint_keypair,
            receiver,
            TEST_CHAIN_ID + 1,
            recent_hash,
            20000,
        );
        let _res = bank.process_transaction(&tx).unwrap();

        let hash_before = bank.evm.chain_state(TEST_CHAIN_ID + 1).state().last_root();

        let state = match *bank.evm.chain_state(TEST_CHAIN_ID + 1).state() {
            EvmState::Incomming(ref i) => i.get_account_state(receiver).unwrap_or_default(),
            EvmState::Committed(_) => panic!(),
        };

        assert_eq!(state.balance, lamports_to_gwei(20000));
        bank.freeze();

        let evm_state = bank.evm.main_chain().state();

        // check that revert keep tx in history, but balances are set to zero
        assert_eq!(evm_state.processed_tx_len(), 0);

        let subchain_evm_state = bank.evm.chain_state(TEST_CHAIN_ID + 1).state();
        log::debug!("subchain_evm_state: {:?}", *subchain_evm_state);
        assert_eq!(subchain_evm_state.processed_tx_len(), 1);
        let account = bank.get_account(&mint_keypair.pubkey()).unwrap_or_default();
        assert_eq!(account.lamports(), LAMPORTS_PER_VLX * 1);

        let state = subchain_evm_state
            .get_account_state(receiver)
            .unwrap_or_default();
        assert_eq!(state.balance, lamports_to_gwei(20000));

        let hash_after = bank.evm.chain_state(TEST_CHAIN_ID + 1).state().last_root();
        // hash updated with nonce increasing
        assert_ne!(hash_before, hash_after);

        // check that bank can be created from parent
        let bank2 = Bank::new_from_parent(&bank, &solana_sdk::pubkey::new_rand(), 1);
        bank2.freeze();
        let new_hash = bank2.evm.chain_state(TEST_CHAIN_ID + 1).state().last_root();

        assert_eq!(new_hash, hash_after);
    }

    #[test]
    fn swap_within_subchain() {
        use {
            solana_evm_loader_program::{precompiles, scope::evm},
            solana_sdk::instruction::AccountMeta,
        };

        fn get_gwei_balance(bank: &Bank, subchain_id: u64, addr: H160) -> U256 {
            bank.evm()
                .side_chains()
                .get(&subchain_id)
                .and_then(|e| e.state().get_account_state(addr))
                .map(|acc| acc.balance)
                .unwrap_or(0.into())
        }

        solana_logger::setup_with("trace");

        let mut rand = evm_state::rand::thread_rng();
        let alice = Pubkey::new_unique();
        let bob = evm::SecretKey::new(&mut rand);
        let bob_addr = bob.to_address();
        let subchain_creation_fee = SUBCHAIN_CREATION_DEPOSIT_VLX * LAMPORTS_PER_VLX;
        let mint_lamports = subchain_creation_fee + 1_000 * LAMPORTS_PER_VLX;
        let (genesis_config, subchain_owner) = create_genesis_config(mint_lamports);
        let mut bank = Bank::new_for_tests(&genesis_config);
        let subchain_id = 0x5677;

        bank.activate_feature(&feature_set::velas::native_swap_in_evm_history::id());
        bank.activate_feature(&feature_set::velas::evm_new_error_handling::id());
        bank.activate_feature(&feature_set::velas::evm_instruction_borsh_serialization::id());
        bank.activate_feature(&feature_set::velas::evm_subchain::id());

        assert_eq!(bank.get_balance(&subchain_owner.pubkey()), mint_lamports);
        assert_eq!(bank.get_balance(&alice), 0);
        assert_eq!(get_gwei_balance(&bank, subchain_id, bob_addr), 0.into());

        let recent_hash = genesis_config.hash();

        let init_subchain_tx = create_subchain_with_preseed(
            &subchain_owner,
            bob_addr,
            subchain_id,
            recent_hash,
            20_000_000,
        );

        bank.process_transaction(&init_subchain_tx).unwrap();
        bank.freeze();
        let bank = Bank::new_from_parent(&Arc::new(bank), &Pubkey::default(), 1);

        assert_eq!(
            bank.get_balance(&subchain_owner.pubkey()),
            mint_lamports - subchain_creation_fee
        );
        assert_eq!(
            get_gwei_balance(&bank, subchain_id, bob_addr),
            lamports_to_gwei(20_000_000)
        );
        assert_eq!(
            get_gwei_balance(&bank, subchain_id, *ETH_TO_VLX_ADDR),
            0.into()
        );

        let swap_within_subchain = {
            let input = [177, 214, 146, 122]
                .into_iter()
                .chain(alice.to_bytes())
                .collect();

            let evm_tx = evm::UnsignedTransaction {
                nonce: 0u32.into(),
                gas_price: evm_state::BURN_GAS_PRICE.into(),
                gas_limit: 300000u32.into(),
                action: evm_state::TransactionAction::Call(*precompiles::ETH_TO_VLX_ADDR),
                value: lamports_to_gwei(3_000_000),
                input,
            }
            .sign(&bob, Some(subchain_id));

            let mut ix = solana_evm_loader_program::send_raw_tx_subchain(
                subchain_owner.pubkey(),
                evm_tx,
                None,
                subchain_id,
            );
            ix.accounts.push(AccountMeta {
                pubkey: alice,
                is_signer: false,
                is_writable: true,
            });

            let message = Message::new(&[ix], Some(&subchain_owner.pubkey()));

            let recent_hash = bank.last_blockhash();
            Transaction::new(&[&subchain_owner], message, recent_hash)
        };

        bank.process_transaction(&swap_within_subchain).unwrap();
        bank.freeze();
        let bank = Bank::new_from_parent(&Arc::new(bank), &Pubkey::default(), 2);

        assert_eq!(bank.get_balance(&alice), 0);
        assert_eq!(
            get_gwei_balance(&bank, subchain_id, bob_addr),
            lamports_to_gwei(17_000_000)
        );
        assert_eq!(
            get_gwei_balance(&bank, subchain_id, *ETH_TO_VLX_ADDR),
            lamports_to_gwei(3_000_000)
        );
    }
}
