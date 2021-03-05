use std::{collections::HashSet, iter, time::Instant};

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};

use evm::{ExitReason, ExitSucceed};
use evm_state::*;
use primitive_types::{H160 as Address, H256, U256};
use sha3::{Digest, Keccak256};

fn name_to_key<S: AsRef<str>>(name: S) -> H160 {
    H256::from_slice(Keccak256::digest(name.as_ref().as_bytes()).as_slice()).into()
}

fn criterion_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("Evm");
    group.throughput(Throughput::Elements(1));

    let code = hex::decode(HELLO_WORLD_CODE).unwrap();
    let data = hex::decode(HELLO_WORLD_ABI).unwrap();
    let expected_result = hex::decode(HELLO_WORLD_RESULT).unwrap();

    let contract = name_to_key("contract");

    const N_ACCOUNTS: usize = 100;
    let accounts: Vec<Address> = (0..N_ACCOUNTS)
        .map(|i| format!("account_{}", i))
        .map(name_to_key)
        .collect();

    // Ensures there no duplicates in addresses.
    assert_eq!(
        iter::once(contract)
            .chain(accounts.iter().copied())
            .collect::<HashSet<Address>>()
            .len(),
        N_ACCOUNTS + 1 // contract + [account]s
    );

    group.bench_function("call_hello", |b| {
        let mut state = EvmState::default();

        for address in iter::once(contract).chain(accounts.iter().copied()) {
            state.set_account_state(address, AccountState::default());
        }

        let slot = state.slot;
        let mut executor =
            Executor::with_config(state, evm::Config::istanbul(), u64::max_value(), slot);

        let exit_reason = executor.with_executor(|executor| {
            executor.transact_create(
                contract,
                U256::zero(),
                code.clone(),
                u64::max_value(),
            )
        });
        assert!(matches!(
            exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));

        let contract_address = TransactionAction::Create.address(contract, U256::zero());
        let mut idx = 0;
        b.iter(|| {
            let exit_reason = black_box(executor.with_executor(|executor| {
                executor.transact_call(
                    accounts[idx % accounts.len()],
                    contract_address,
                    U256::zero(),
                    data.to_vec(),
                    u64::max_value(),
                )
            }));

            assert!(matches!(
                exit_reason,
                (ExitReason::Succeed(ExitSucceed::Returned), ref result) if result == &expected_result
            ));

            idx += 1;
        });
    });

    group.bench_function("call_hello_with_executor_recreate", |b| {
        let mut executor = Executor::with_config(
            EvmState::default(),
            evm::Config::istanbul(),
            u64::max_value(),
            0,
        );

        let exit_reason = executor.with_executor(|executor| {
            executor.transact_create(contract, U256::zero(), code.clone(), u64::max_value())
        });
        assert!(matches!(
            exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));

        let mut state = executor.deconstruct();
        state.commit();

        let contract_address = TransactionAction::Create.address(contract, U256::zero());
        let mut idx = 0;
        b.iter(|| {
            let mut executor =
                Executor::with_config(state.clone(), evm::Config::istanbul(), u64::max_value(), state.slot);

            let exit_reason = black_box(executor.with_executor(|executor| {
                executor.transact_call(
                    accounts[idx % accounts.len()],
                    contract_address,
                    U256::zero(),
                    data.to_vec(),
                    u64::max_value(),
                )
            }));

            assert!(matches!(
                exit_reason,
                (ExitReason::Succeed(ExitSucceed::Returned), ref result) if result == &expected_result
            ));

            idx += 1;
        });
    });

    for n_forks in &[0, 1, 10, 50, 100, 1000] {
        group.bench_with_input(
            BenchmarkId::new("call_hello_on_frozen_forks", n_forks),
            n_forks,
            |b, n_forks| {
                let mut state = EvmState::default();

                for address in iter::once(contract).chain(accounts.iter().copied()) {
                    state.set_account_state(address, AccountState::default());
                }

                let slot = state.slot;
                let mut executor =
                    Executor::with_config(state, evm::Config::istanbul(), u64::max_value(), slot);
                let create_transaction_result = executor.with_executor(|executor| {
                    executor.transact_create(contract, U256::zero(), code.clone(), u64::max_value())
                });
                assert!(matches!(
                    create_transaction_result,
                    ExitReason::Succeed(ExitSucceed::Returned)
                ));

                let mut state = executor.deconstruct();
                state.commit();

                for new_slot in (slot + 1)..=*n_forks {
                    // state.freeze();
                    state = state.fork(new_slot);
                }

                let contract = TransactionAction::Create.address(contract, U256::zero());

                let accounts = &accounts;
                let data = data.clone();
                let expected_result = &expected_result;

                b.iter_custom(move |iters| {
                    let mut executor = Executor::with_config(
                        state.clone(),
                        evm::Config::istanbul(),
                        u64::max_value(),
                        state.slot,
                    );

                    let start = Instant::now();

                    for idx in 0..iters {
                        let caller = accounts[idx as usize % accounts.len()];
                        let call_transaction_result =
                            black_box(executor.with_executor(|executor| {
                                executor.transact_call(
                                    caller,
                                    contract,
                                    U256::zero(),
                                    data.to_vec(),
                                    u64::max_value(),
                                )
                            }));
                        assert!(matches!(
                            call_transaction_result,
                            (ExitReason::Succeed(ExitSucceed::Returned), ref result) if result == expected_result
                        ));
                    }

                    start.elapsed()
                });
            },
        );
    }

    group.bench_function("call_hello_on_dumped_state", |b| {
        let mut state = EvmState::default();

        iter::once(contract)
            .chain(accounts.iter().copied())
            .for_each(|address| state.set_account_state(address, AccountState::default()));

        state.commit();

        let slot = state.slot;
        let mut executor =
            Executor::with_config(state, evm::Config::istanbul(), u64::max_value(), slot);

        let exit_reason = executor.with_executor(|executor| {
            executor.transact_create(contract, U256::zero(), code.clone(), u64::max_value())
        });
        assert!(matches!(
            exit_reason,
            ExitReason::Succeed(ExitSucceed::Returned)
        ));

        let mut state = executor.deconstruct();
        state.commit();

        let contract_address = TransactionAction::Create.address(contract, U256::zero());
        let mut idx = 0;
        b.iter(|| {
            let mut executor =
                Executor::with_config(state.clone(), evm::Config::istanbul(), u64::max_value(), state.slot);

            let exit_reason = executor.with_executor(|executor| {
                executor.transact_call(
                    accounts[idx % accounts.len()],
                    contract_address,
                    U256::zero(),
                    data.to_vec(),
                    u64::max_value(),
                )
            });

            assert!(matches!(
                exit_reason,
                (ExitReason::Succeed(ExitSucceed::Returned), ref result) if result == &expected_result
            ));

            idx += 1;
        });
    });

    group.finish();
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
