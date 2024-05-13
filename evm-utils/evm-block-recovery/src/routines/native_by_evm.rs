use evm_state::H256;
use solana_sdk::{evm_loader::check_id as is_evm_loader, evm_state::check_id as is_evm_state};
use solana_transaction_status::TransactionWithStatusMeta;
use std::str::FromStr;

use crate::{cli::NativeByEvmArgs, error::RoutineResult, ledger};

// NOTE: remove panics if routine as service embedding is required

pub async fn native_by_evm(
    creds: Option<String>,
    instance: String,
    args: NativeByEvmArgs,
) -> RoutineResult {
    let NativeByEvmArgs { hash } = args;

    let hash = H256::from_str(&hash).unwrap();

    let ledger = ledger::with_params(creds, instance).await?;

    let receipt = ledger.get_evm_confirmed_receipt(&hash).await.unwrap();

    let (block_number, index) = match receipt {
        Some(receipt) => (receipt.block_number, receipt.index),
        None => {
            panic!("Receipt for transaction {hash} does not exist");
        }
    };

    let evm_header = ledger
        .get_evm_confirmed_block_header(block_number)
        .await
        .unwrap();

    let native_block = ledger
        .get_confirmed_block(evm_header.native_chain_slot)
        .await
        .unwrap();

    let evm_related_txs = native_block
        .transactions
        .into_iter()
        .filter(is_evm_related_tx)
        .collect::<Vec<_>>();

    let result_tx = &evm_related_txs[index as usize - 1];

    let logs = &result_tx.get_status_meta().unwrap().log_messages.unwrap();

    let mut evm_hash_found = false;

    for log in logs {
        if log.contains(&format!("{hash:?}")) {
            evm_hash_found = true;
            break;
        }
    }

    let signature = result_tx.transaction_signature();

    log::info!("EVM Transaction Hash: {hash:?}");
    log::info!("Native Transaction Signature: {signature}");
    if !evm_hash_found {
        log::warn!("Logs do NOT contain EVM Transaction Hash: {hash:?}");
        log::debug!("{logs:?}");
    }

    Ok(())
}

fn is_evm_related_tx(tx: &TransactionWithStatusMeta) -> bool {
    let tx_keys = tx.account_keys();

    let contains_evm_state_key = tx_keys.iter().find(|key| is_evm_state(key)).is_some();
    let contains_evm_loadr_key = tx_keys.iter().find(|key| is_evm_loader(key)).is_some();

    contains_evm_state_key && contains_evm_loadr_key
}
