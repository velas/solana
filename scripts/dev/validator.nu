#!/usr/bin/env nu

$env.RUST_LOG = "warn,solana_metrics=warn,solana_core=warn,solana_poh=warn,rpc=trace"
$env.NDEBUG = 1

./target/release/velas-validator --no-duplicate-instance-check --max-genesis-archive-unpacked-size 1073741824 --entrypoint bootstrap.testnet.velas.com:8001 --ledger ../ledger-testnet --log - --no-poh-speed-test --enable-rpc-transaction-history --rpc-port 8899 --dynamic-port-range 8001-8014 --snapshot-interval-slots 200 --enable-cpi-and-log-storage --rpc-bigtable-timeout 10 --no-check-vote-account --limit-ledger-size 100000000  --expected-shred-version 17211 --no-port-check  --no-os-network-limits-test