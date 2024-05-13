use std::str::FromStr;

use solana_sdk::{message::VersionedMessage, pubkey::Pubkey, signature::Signature, system_program};
use solana_transaction_status::TransactionWithStatusMeta;

use crate::{
    cli::{AccountLedgerArgs, CsvSeparator},
    error::{AppError, RoutineResult},
    ledger,
};

// NOTE: remove panics if routine as service embedding is required

pub async fn account_ledger(
    creds: Option<String>,
    instance: String,
    args: AccountLedgerArgs,
) -> RoutineResult {
    let AccountLedgerArgs {
        address,
        before_signature,
        until_signature,
        limit,
        output,
        separator,
    } = args;

    let before_signature = before_signature.map(|x| {
        solana_sdk::signature::Signature::from_str(&x).expect(&format!("Invalid signature: {}", x))
    });

    let until_signature = until_signature.map(|x| {
        solana_sdk::signature::Signature::from_str(&x).expect(&format!("Invalid signature: {}", x))
    });

    let ledger = ledger::with_params(creds, instance).await?;

    let address = Pubkey::from_str(&address).unwrap();

    let signatures = ledger
        .get_confirmed_signatures_for_address(
            &address,
            before_signature.as_ref(),
            until_signature.as_ref(),
            limit,
        )
        .await
        .map_err(|source| AppError::GetSignatures { source })?;

    log::info!("{} signatures discovered", signatures.len());

    struct LedgerEntry {
        signature: Signature,
        is_transfer: bool,
        counterparty: Pubkey,
        block_time: i64,
        pre_balance: u64,
        post_balance: u64,
    }

    let mut result_ledger: Vec<LedgerEntry> = Vec::with_capacity(signatures.len());
    let mut txs_count = 0;

    for (status, _tx_slot_pos) in signatures {
        let signature = status.signature;
        let block_time = status.block_time.expect("Block has no timestamp");

        if txs_count % 100 == 0 {
            log::info!("{txs_count} transactions processed...");
        }

        let transaction = ledger
            .get_confirmed_transaction(&signature)
            .await
            .unwrap()
            .unwrap();

        txs_count += 1;

        let tx_with_meta = match &transaction.tx_with_meta {
            TransactionWithStatusMeta::Complete(complete) => complete.clone(),
            TransactionWithStatusMeta::MissingMetadata(_) => {
                panic!("Transaction {} has no metadata!", &signature)
            }
        };

        let message = match transaction.get_transaction().message {
            VersionedMessage::Legacy(legacy) => legacy,
            VersionedMessage::V0(_v0) => panic!(
                "Unsupported `message` version for transaction {}",
                &signature
            ),
        };

        let mut account_keys = message.account_keys.clone();

        let balance_idx = account_keys
            .iter()
            .position(|a| a == &address)
            .expect("Account should be present in account_keys");

        account_keys.retain(|e| e != &system_program::ID && e != &address);

        let pre_balance = tx_with_meta.meta.pre_balances[balance_idx];
        let post_balance = tx_with_meta.meta.post_balances[balance_idx];

        let is_transfer = account_keys.len() == 1;
        let counterparty = account_keys[0];

        result_ledger.push(LedgerEntry {
            signature,
            is_transfer,
            counterparty,
            block_time,
            pre_balance,
            post_balance,
        });
    }

    let separator = match separator {
        CsvSeparator::Comma => ',',
        CsvSeparator::Semicolon => ';',
        CsvSeparator::Tab => '\t',
    };

    let mut output_buffer = String::new();

    output_buffer.push_str(&format!(
        "Signature{separator}Is Transfer{separator}Counterparty{separator}Unix Timestamp (s){separator}Change (VLX){separator}Post Balance (VLX)\n"
    ));

    for entry in result_ledger {
        let balance_change =
            (entry.post_balance as i64 - entry.pre_balance as i64) as f64 / 1_000_000_000.;
        let post_balance = entry.post_balance as f64 / 1_000_000_000.;

        output_buffer.push_str(&format!(
            "{}{separator}{}{separator}{}{separator}{}{separator}{}{separator}{}\n",
            entry.signature,
            entry.is_transfer,
            entry.counterparty,
            entry.block_time,
            balance_change,
            post_balance
        ));
    }

    std::fs::write(output, output_buffer).expect("Write output ledger file failed");

    Ok(())
}
