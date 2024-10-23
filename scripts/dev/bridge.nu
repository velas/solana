#!/usr/bin/env nu

cargo build --release --bin evm-bridge

let $id = $"($env.HOME)/.config/velas/id.json"

# $env.RUST_LOG = "info,rpc=trace,evm_bridge=trace,evm_bridge::pool=warn"
$env.RUST_LOG = "evm_bridge::pool=trace"

./target/release/evm-bridge $id http://127.0.0.1:8899 127.0.0.1:8545 1221
# ./target/release/evm-bridge $id http://127.0.0.1:8899 127.0.0.1:8545 1221 --subchain