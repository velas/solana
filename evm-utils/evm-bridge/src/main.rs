use log::*;

use std::sync::Arc;
use std::thread::sleep;
use std::time::Duration;
use std::{collections::HashMap, net::SocketAddr};

use evm_rpc::basic::BasicERPC;
use evm_rpc::bridge::BridgeERPC;
use evm_rpc::chain_mock::ChainMockERPC;
use evm_rpc::error::*;
use evm_rpc::*;
use evm_state::*;
use sha3::{Digest, Keccak256};

use jsonrpc_core::Result;
use serde_json::json;
use snafu::ResultExt;

use solana_account_decoder::{parse_token::UiTokenAmount, UiAccount};
use solana_evm_loader_program::{scope::*, tx_chunks::TxChunks};
use solana_sdk::{
    clock::DEFAULT_TICKS_PER_SECOND, commitment_config::CommitmentLevel, instruction::AccountMeta,
};

use solana_runtime::commitment::BlockCommitmentArray;
use solana_sdk::{
    clock::{Slot, UnixTimestamp},
    commitment_config::CommitmentConfig,
    epoch_info::EpochInfo,
    epoch_schedule::EpochSchedule,
    message::Message,
    signature::Signer,
    signers::Signers,
    system_instruction, transaction,
};
use solana_transaction_status::{
    EncodedConfirmedBlock, EncodedConfirmedTransaction, TransactionStatus, UiTransactionEncoding,
};

use solana_client::{
    rpc_client::RpcClient, rpc_config::*, rpc_request::RpcRequest,
    rpc_response::Response as RpcResponse, rpc_response::*,
};

use solana_core::rpc::RpcSol;

use std::result::Result as StdResult;

type EvmResult<T> = StdResult<T, evm_rpc::Error>;
type FutureEvmResult<T> = EvmResult<T>;

pub struct EvmBridge {
    evm_chain_id: U256,
    key: solana_sdk::signature::Keypair,
    accounts: HashMap<evm_state::Address, evm_state::SecretKey>,
    rpc_client: RpcClient,
}

impl EvmBridge {
    fn new(evm_chain_id: U256, keypath: &str, evm_keys: Vec<SecretKey>, addr: String) -> Self {
        info!("EVM chain id {}", evm_chain_id);

        let accounts = evm_keys
            .into_iter()
            .map(|secret_key| {
                let public_key =
                    evm_state::PublicKey::from_secret_key(&evm_state::SECP256K1, &secret_key);
                let public_key = evm_state::addr_from_public_key(&public_key);
                (public_key, secret_key)
            })
            .collect();

        info!("Trying to create rpc client with addr: {}", addr);
        let rpc_client = RpcClient::new(addr);

        info!("Loading keypair from: {}", keypath);
        Self {
            evm_chain_id,
            key: solana_sdk::signature::read_keypair_file(&keypath).unwrap(),
            accounts,
            rpc_client,
        }
    }

    /// Wrap evm tx into solana, optionally add meta keys, to solana signature.
    fn send_tx(&self, tx: evm::Transaction) -> FutureEvmResult<Hex<H256>> {
        let hash = tx.signing_hash();
        let bytes = bincode::serialize(&tx).unwrap();

        if bytes.len() > evm::TX_MTU {
            debug!("Sending tx = {}, by chunks", hash);
            match deploy_big_tx(&self.rpc_client, &self.key, &tx) {
                Ok(_tx) => return Ok(Hex(hash)),
                Err(e) => {
                    error!("Error creating big tx = {}", e);
                    return Err(e);
                }
            }
        }

        debug!(
            "Printing tx_info from = {:?}, to = {:?}, nonce = {}, chain_id = {:?}",
            tx.caller(),
            tx.address(),
            tx.nonce,
            tx.signature.chain_id()
        );

        let mut meta_keys = vec![];

        // Shortcut for swap tokens to native, will add solana account to transaction.
        if let TransactionAction::Call(addr) = tx.action {
            use solana_evm_loader_program::precompiles::*;

            if addr == *ETH_TO_SOL_ADDR {
                debug!("Found transferToNative transaction");
                match ETH_TO_SOL_CODE.parse_abi(&tx.input) {
                    Ok(pk) => {
                        info!("Adding account to meta = {}", pk);
                        meta_keys.push(pk)
                    }
                    Err(e) => {
                        error!("Error in parsing abi = {}", e);
                    }
                }
            }
        }

        let mut ix = solana_evm_loader_program::send_raw_tx(self.key.pubkey(), tx);

        // Add meta accounts as additional arguments
        for account in meta_keys {
            ix.accounts.push(AccountMeta::new(account, false))
        }

        let message = Message::new(&[ix], Some(&self.key.pubkey()));
        let mut send_raw_tx: solana::Transaction = solana::Transaction::new_unsigned(message);

        debug!("Getting block hash");
        let (blockhash, _fee_calculator, _) = self
            .rpc_client
            .get_recent_blockhash_with_commitment(CommitmentConfig::default())
            .unwrap()
            .value;

        send_raw_tx.sign(&vec![&self.key], blockhash);
        debug!("Sending tx = {:?}", send_raw_tx);

        self.rpc_client
            .send_transaction_with_config(&send_raw_tx, RpcSendTransactionConfig::default())
            .map(|_| Hex(hash))
            .as_proxy_error()
    }
}

macro_rules! proxy_evm_rpc {
    ($rpc: expr, $rpc_call:ident $(, $calls:expr)*) => (
        {
        trace!("evm proxy received {}", stringify!($rpc_call));
        RpcClient::send(&$rpc, RpcRequest::$rpc_call, json!([$($calls,)*]))
            .map_err(|e| {
                error!("Json rpc error = {:?}", e);
                evm_rpc::Error::ProxyRpcError{
                    source: e.into()
                }
            })
        }
    )
}

pub struct BridgeERPCImpl;

impl BridgeERPC for BridgeERPCImpl {
    type Metadata = Arc<EvmBridge>;

    fn accounts(&self, meta: Self::Metadata) -> EvmResult<Vec<Hex<Address>>> {
        Ok(meta.accounts.iter().map(|(k, _)| Hex(*k)).collect())
    }

    fn sign(
        &self,
        _meta: Self::Metadata,
        _address: Hex<Address>,
        _data: Bytes,
    ) -> EvmResult<Bytes> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn send_transaction(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
    ) -> FutureEvmResult<Hex<H256>> {
        let address = tx.from.map(|a| a.0).unwrap_or_default();

        debug!("send_transaction from = {}", address);

        let secret_key = meta.accounts.get(&address).unwrap();
        let nonce = tx
            .nonce
            .map(|a| a.0)
            .or_else(|| meta.rpc_client.get_evm_transaction_count(&address).ok())
            .unwrap_or_default();
        let tx_create = evm::UnsignedTransaction {
            nonce,
            gas_price: tx.gas_price.map(|a| a.0).unwrap_or_else(|| 0.into()),
            gas_limit: tx.gas.map(|a| a.0).unwrap_or_else(|| 30000000.into()),
            action: tx
                .to
                .map(|a| evm::TransactionAction::Call(a.0))
                .unwrap_or(evm::TransactionAction::Create),
            value: tx.value.map(|a| a.0).unwrap_or_else(|| 0.into()),
            input: tx.data.map(|a| a.0).unwrap_or_default(),
        };

        let tx = tx_create.sign(&secret_key, Some(meta.evm_chain_id.as_u64()));

        meta.send_tx(tx)
    }

    fn send_raw_transaction(
        &self,
        meta: Self::Metadata,
        bytes: Bytes,
    ) -> FutureEvmResult<Hex<H256>> {
        debug!("send_raw_transaction");

        let tx: evm::Transaction = rlp::decode(&bytes.0).unwrap();
        let unsigned_tx: evm::UnsignedTransaction = tx.clone().into();
        let hash = unsigned_tx.signing_hash(Some(meta.evm_chain_id.as_u64()));
        debug!("loaded tx_hash = {}", hash);
        meta.send_tx(tx)
    }

    fn gas_price(&self, _meta: Self::Metadata) -> EvmResult<Hex<Gas>> {
        //TODO: Add gas logic
        Ok(Hex(1.into()))
    }

    fn compilers(&self, _meta: Self::Metadata) -> EvmResult<Vec<String>> {
        Err(evm_rpc::Error::Unimplemented {})
    }
}

pub struct ChainMockERPCProxy;
impl ChainMockERPC for ChainMockERPCProxy {
    type Metadata = Arc<EvmBridge>;

    fn network_id(&self, meta: Self::Metadata) -> EvmResult<String> {
        // NOTE: also we can get chain id from meta, but expects the same value
        Ok(format!("{}", meta.evm_chain_id))
    }

    fn chain_id(&self, meta: Self::Metadata) -> EvmResult<Hex<u64>> {
        Ok(Hex(meta.evm_chain_id.as_u64()))
    }

    // TODO: Add network info
    fn is_listening(&self, _meta: Self::Metadata) -> EvmResult<bool> {
        Ok(true)
    }

    fn peer_count(&self, _meta: Self::Metadata) -> EvmResult<Hex<usize>> {
        Ok(Hex(0))
    }

    fn sha3(&self, _meta: Self::Metadata, bytes: Bytes) -> EvmResult<Hex<H256>> {
        Ok(Hex(H256::from_slice(
            Keccak256::digest(bytes.0.as_slice()).as_slice(),
        )))
    }

    fn client_version(&self, _meta: Self::Metadata) -> EvmResult<String> {
        Ok(String::from("SolanaEvm/v0.1.0"))
    }

    fn protocol_version(&self, _meta: Self::Metadata) -> EvmResult<String> {
        Ok(String::from("0"))
    }

    fn is_syncing(&self, _meta: Self::Metadata) -> EvmResult<bool> {
        Ok(false)
    }

    fn coinbase(&self, _meta: Self::Metadata) -> EvmResult<Hex<Address>> {
        Ok(Hex(Address::from_low_u64_be(0)))
    }

    fn is_mining(&self, _meta: Self::Metadata) -> EvmResult<bool> {
        Ok(false)
    }

    fn hashrate(&self, _meta: Self::Metadata) -> EvmResult<String> {
        Ok(String::from("0x00"))
    }

    fn block_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _full: bool,
    ) -> EvmResult<Option<RPCBlock>> {
        Ok(Some(RPCBlock {
            number: U256::zero().into(),
            hash: H256::zero().into(),
            parent_hash: H256::zero().into(),
            size: 0.into(),
            gas_limit: Gas::zero().into(),
            gas_used: Gas::zero().into(),
            timestamp: 0.into(),
            transactions: Either::Left(vec![]),
            nonce: 0.into(),
            sha3_uncles: H256::zero().into(),
            logs_bloom: H256::zero().into(), // H2048
            transactions_root: H256::zero().into(),
            state_root: H256::zero().into(),
            receipts_root: H256::zero().into(),
            miner: Address::zero().into(),
            difficulty: U256::zero().into(),
            total_difficulty: U256::zero().into(),
            extra_data: vec![].into(),
            uncles: vec![],
        }))
    }

    fn block_by_number(
        &self,
        meta: Self::Metadata,
        block: String,
        full: bool,
    ) -> EvmResult<Option<RPCBlock>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetBlockByNumber, block, full)
    }

    fn block_transaction_count_by_number(
        &self,
        _meta: Self::Metadata,
        _block: String,
    ) -> EvmResult<Option<Hex<usize>>> {
        Ok(None)
    }

    fn block_transaction_count_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
    ) -> EvmResult<Option<Hex<usize>>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn uncle_by_block_hash_and_index(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _uncle_id: Hex<U256>,
    ) -> EvmResult<Option<RPCBlock>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn uncle_by_block_number_and_index(
        &self,
        _meta: Self::Metadata,
        _block: String,
        _uncle_id: Hex<U256>,
    ) -> EvmResult<Option<RPCBlock>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn block_uncles_count_by_hash(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
    ) -> EvmResult<Option<Hex<usize>>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn block_uncles_count_by_number(
        &self,
        _meta: Self::Metadata,
        _block: String,
    ) -> EvmResult<Option<Hex<usize>>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn transaction_by_block_hash_and_index(
        &self,
        _meta: Self::Metadata,
        _block_hash: Hex<H256>,
        _tx_id: Hex<U256>,
    ) -> EvmResult<Option<RPCTransaction>> {
        Err(evm_rpc::Error::Unimplemented {})
    }

    fn transaction_by_block_number_and_index(
        &self,
        _meta: Self::Metadata,
        _block: String,
        _tx_id: Hex<U256>,
    ) -> EvmResult<Option<RPCTransaction>> {
        Err(evm_rpc::Error::Unimplemented {})
    }
}

pub struct BasicERPCProxy;
impl BasicERPC for BasicERPCProxy {
    type Metadata = Arc<EvmBridge>;

    // The same as get_slot
    fn block_number(&self, meta: Self::Metadata) -> EvmResult<Hex<usize>> {
        proxy_evm_rpc!(meta.rpc_client, EthBlockNumber)
    }

    fn balance(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<String>,
    ) -> EvmResult<Hex<U256>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetBalance, address, block)
    }

    fn storage_at(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        data: Hex<H256>,
        block: Option<String>,
    ) -> EvmResult<Hex<H256>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetStorageAt, address, data, block)
    }

    fn transaction_count(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<String>,
    ) -> EvmResult<Hex<U256>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetTransactionCount, address, block)
    }

    fn code(
        &self,
        meta: Self::Metadata,
        address: Hex<Address>,
        block: Option<String>,
    ) -> EvmResult<Bytes> {
        proxy_evm_rpc!(meta.rpc_client, EthGetCode, address, block)
    }

    fn transaction_by_hash(
        &self,
        meta: Self::Metadata,
        tx_hash: Hex<H256>,
    ) -> EvmResult<Option<RPCTransaction>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetTransactionByHash, tx_hash)
    }

    fn transaction_receipt(
        &self,
        meta: Self::Metadata,
        tx_hash: Hex<H256>,
    ) -> EvmResult<Option<RPCReceipt>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetTransactionReceipt, tx_hash)
    }

    fn call(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        block: Option<String>,
    ) -> EvmResult<Bytes> {
        proxy_evm_rpc!(meta.rpc_client, EthCall, tx, block)
    }

    fn estimate_gas(
        &self,
        meta: Self::Metadata,
        tx: RPCTransaction,
        block: Option<String>,
    ) -> EvmResult<Hex<Gas>> {
        proxy_evm_rpc!(meta.rpc_client, EthEstimateGas, tx, block)
    }

    fn logs(&self, meta: Self::Metadata, log_filter: RPCLogFilter) -> EvmResult<Vec<RPCLog>> {
        proxy_evm_rpc!(meta.rpc_client, EthGetLogs, log_filter)
    }
}

macro_rules! proxy_sol_rpc {
    ($rpc: expr, $rpc_call:ident $(, $calls:expr)*) => (
        {
        debug!("proxy received {}", stringify!($rpc_call));
        RpcClient::send(&$rpc, RpcRequest::$rpc_call, json!([$($calls,)*]))
            .map_err(|e| {
                error!("Json rpc error = {:?}", e);
                jsonrpc_core::Error::internal_error()
            })
        }
    )
}

pub struct RpcSolProxy;
impl RpcSol for RpcSolProxy {
    type Metadata = Arc<EvmBridge>;

    fn confirm_transaction(
        &self,
        meta: Self::Metadata,
        id: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<bool>> {
        proxy_sol_rpc!(meta.rpc_client, GetConfirmedTransaction, id, commitment)
    }

    fn get_account_info(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<RpcResponse<Option<UiAccount>>> {
        proxy_sol_rpc!(meta.rpc_client, GetAccountInfo, pubkey_str, config)
    }

    fn get_multiple_accounts(
        &self,
        meta: Self::Metadata,
        pubkey_strs: Vec<String>,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<RpcResponse<Vec<Option<UiAccount>>>> {
        proxy_sol_rpc!(meta.rpc_client, GetMultipleAccounts, pubkey_strs, config)
    }

    fn get_minimum_balance_for_rent_exemption(
        &self,
        meta: Self::Metadata,
        data_len: usize,
        commitment: Option<CommitmentConfig>,
    ) -> Result<u64> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetMinimumBalanceForRentExemption,
            data_len,
            commitment
        )
    }

    fn get_program_accounts(
        &self,
        meta: Self::Metadata,
        program_id_str: String,
        config: Option<RpcProgramAccountsConfig>,
    ) -> Result<Vec<RpcKeyedAccount>> {
        proxy_sol_rpc!(meta.rpc_client, GetProgramAccounts, program_id_str, config)
    }

    fn get_inflation_governor(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcInflationGovernor> {
        proxy_sol_rpc!(meta.rpc_client, GetInflationGovernor, commitment)
    }

    fn get_inflation_rate(&self, meta: Self::Metadata) -> Result<RpcInflationRate> {
        proxy_sol_rpc!(meta.rpc_client, GetInflationRate)
    }

    fn get_epoch_schedule(&self, meta: Self::Metadata) -> Result<EpochSchedule> {
        proxy_sol_rpc!(meta.rpc_client, GetEpochSchedule)
    }

    fn get_balance(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<u64>> {
        proxy_sol_rpc!(meta.rpc_client, GetBalance, pubkey_str, commitment)
    }

    fn get_cluster_nodes(&self, meta: Self::Metadata) -> Result<Vec<RpcContactInfo>> {
        proxy_sol_rpc!(meta.rpc_client, GetClusterNodes)
    }

    fn get_epoch_info(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<EpochInfo> {
        proxy_sol_rpc!(meta.rpc_client, GetEpochInfo, commitment)
    }

    fn get_block_commitment(
        &self,
        meta: Self::Metadata,
        block: Slot,
    ) -> Result<RpcBlockCommitment<BlockCommitmentArray>> {
        proxy_sol_rpc!(meta.rpc_client, GetBlockCommitment, block)
    }

    fn get_genesis_hash(&self, meta: Self::Metadata) -> Result<String> {
        proxy_sol_rpc!(meta.rpc_client, GetGenesisHash)
    }

    fn get_leader_schedule(
        &self,
        meta: Self::Metadata,
        slot: Option<Slot>,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Option<RpcLeaderSchedule>> {
        proxy_sol_rpc!(meta.rpc_client, GetLeaderSchedule, slot, commitment)
    }

    fn get_recent_blockhash(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<RpcBlockhashFeeCalculator>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetMinimumBalanceForRentExemption,
            commitment
        )
    }

    fn get_fees(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<RpcFees>> {
        proxy_sol_rpc!(meta.rpc_client, GetFees, commitment)
    }

    fn get_fee_calculator_for_blockhash(
        &self,
        meta: Self::Metadata,
        blockhash: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<Option<RpcFeeCalculator>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetFeeCalculatorForBlockhash,
            blockhash,
            commitment
        )
    }

    fn get_fee_rate_governor(
        &self,
        meta: Self::Metadata,
    ) -> Result<RpcResponse<RpcFeeRateGovernor>> {
        proxy_sol_rpc!(meta.rpc_client, GetFeeRateGovernor)
    }

    fn get_signature_confirmation(
        &self,
        meta: Self::Metadata,
        signature_str: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Option<RpcSignatureConfirmation>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetSignatureConfirmation,
            signature_str,
            commitment
        )
    }

    fn get_signature_status(
        &self,
        meta: Self::Metadata,
        signature_str: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<Option<transaction::Result<()>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetSignatureStatus,
            signature_str,
            commitment
        )
    }

    fn get_signature_statuses(
        &self,
        meta: Self::Metadata,
        signature_strs: Vec<String>,
        config: Option<RpcSignatureStatusConfig>,
    ) -> Result<RpcResponse<Vec<Option<TransactionStatus>>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetSignatureStatuses,
            signature_strs,
            config
        )
    }

    fn get_slot(&self, meta: Self::Metadata, commitment: Option<CommitmentConfig>) -> Result<u64> {
        proxy_sol_rpc!(meta.rpc_client, GetSlot, commitment)
    }

    fn get_transaction_count(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<u64> {
        proxy_sol_rpc!(meta.rpc_client, GetTransactionCount, commitment)
    }

    fn get_total_supply(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<u64> {
        proxy_sol_rpc!(meta.rpc_client, GetTotalSupply, commitment)
    }

    fn get_largest_accounts(
        &self,
        meta: Self::Metadata,
        config: Option<RpcLargestAccountsConfig>,
    ) -> Result<RpcResponse<Vec<RpcAccountBalance>>> {
        proxy_sol_rpc!(meta.rpc_client, GetLargestAccounts, config)
    }

    fn get_supply(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<RpcSupply>> {
        proxy_sol_rpc!(meta.rpc_client, GetSupply, commitment)
    }

    fn request_airdrop(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        lamports: u64,
        commitment: Option<CommitmentConfig>,
    ) -> Result<String> {
        proxy_sol_rpc!(
            meta.rpc_client,
            RequestAirdrop,
            pubkey_str,
            lamports,
            commitment
        )
    }

    fn send_transaction(
        &self,
        meta: Self::Metadata,
        data: String,
        config: Option<RpcSendTransactionConfig>,
    ) -> Result<String> {
        proxy_sol_rpc!(meta.rpc_client, SendTransaction, data, config)
    }

    fn simulate_transaction(
        &self,
        meta: Self::Metadata,
        data: String,
        config: Option<RpcSimulateTransactionConfig>,
    ) -> Result<RpcResponse<RpcSimulateTransactionResult>> {
        proxy_sol_rpc!(meta.rpc_client, SimulateTransaction, data, config)
    }

    fn get_slot_leader(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<String> {
        proxy_sol_rpc!(meta.rpc_client, GetSlotLeader, commitment)
    }

    fn minimum_ledger_slot(&self, meta: Self::Metadata) -> Result<Slot> {
        proxy_sol_rpc!(meta.rpc_client, MinimumLedgerSlot)
    }

    fn get_vote_accounts(
        &self,
        meta: Self::Metadata,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcVoteAccountStatus> {
        proxy_sol_rpc!(meta.rpc_client, GetVoteAccounts, commitment)
    }

    fn validator_exit(&self, meta: Self::Metadata) -> Result<bool> {
        proxy_sol_rpc!(meta.rpc_client, ValidatorExit)
    }

    fn get_identity(&self, meta: Self::Metadata) -> Result<RpcIdentity> {
        proxy_sol_rpc!(meta.rpc_client, GetMinimumBalanceForRentExemption)
    }

    fn get_version(&self, meta: Self::Metadata) -> Result<RpcVersionInfo> {
        proxy_sol_rpc!(meta.rpc_client, GetVersion)
    }

    fn set_log_filter(&self, meta: Self::Metadata, filter: String) -> Result<()> {
        proxy_sol_rpc!(meta.rpc_client, SetLogFilter, filter)
    }

    fn get_confirmed_block(
        &self,
        meta: Self::Metadata,
        slot: Slot,
        encoding: Option<UiTransactionEncoding>,
    ) -> Result<Option<EncodedConfirmedBlock>> {
        proxy_sol_rpc!(meta.rpc_client, GetConfirmedBlock, slot, encoding)
    }

    fn get_confirmed_blocks(
        &self,
        meta: Self::Metadata,
        start_slot: Slot,
        end_slot: Option<Slot>,
    ) -> Result<Vec<Slot>> {
        proxy_sol_rpc!(meta.rpc_client, GetConfirmedBlocks, start_slot, end_slot)
    }

    fn get_block_time(&self, meta: Self::Metadata, slot: Slot) -> Result<Option<UnixTimestamp>> {
        proxy_sol_rpc!(meta.rpc_client, GetBlockTime, slot)
    }

    fn get_confirmed_transaction(
        &self,
        meta: Self::Metadata,
        signature_str: String,
        encoding: Option<UiTransactionEncoding>,
    ) -> Result<Option<EncodedConfirmedTransaction>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetConfirmedTransaction,
            signature_str,
            encoding
        )
    }

    fn get_confirmed_signatures_for_address(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        start_slot: Slot,
        end_slot: Slot,
    ) -> Result<Vec<String>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetConfirmedSignaturesForAddress,
            pubkey_str,
            start_slot,
            end_slot
        )
    }

    fn get_confirmed_signatures_for_address2(
        &self,
        meta: Self::Metadata,
        address: String,
        config: Option<RpcGetConfirmedSignaturesForAddress2Config>,
    ) -> Result<Vec<RpcConfirmedTransactionStatusWithSignature>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetConfirmedSignaturesForAddress2,
            address,
            config
        )
    }

    fn get_first_available_block(&self, meta: Self::Metadata) -> Result<Slot> {
        proxy_sol_rpc!(meta.rpc_client, GetFirstAvailableBlock)
    }

    fn get_stake_activation(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        config: Option<RpcStakeConfig>,
    ) -> Result<RpcStakeActivation> {
        proxy_sol_rpc!(meta.rpc_client, GetStakeActivation, pubkey_str, config)
    }

    fn get_token_account_balance(
        &self,
        meta: Self::Metadata,
        pubkey_str: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<UiTokenAmount>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetTokenAccountBalance,
            pubkey_str,
            commitment
        )
    }

    fn get_token_supply(
        &self,
        meta: Self::Metadata,
        mint_str: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<UiTokenAmount>> {
        proxy_sol_rpc!(meta.rpc_client, GetTokenSupply, mint_str, commitment)
    }

    fn get_token_largest_accounts(
        &self,
        meta: Self::Metadata,
        mint_str: String,
        commitment: Option<CommitmentConfig>,
    ) -> Result<RpcResponse<Vec<RpcTokenAccountBalance>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetTokenLargestAccounts,
            mint_str,
            commitment
        )
    }

    fn get_token_accounts_by_owner(
        &self,
        meta: Self::Metadata,
        owner_str: String,
        token_account_filter: RpcTokenAccountsFilter,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<RpcResponse<Vec<RpcKeyedAccount>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetTokenAccountsByOwner,
            owner_str,
            token_account_filter,
            config
        )
    }

    fn get_token_accounts_by_delegate(
        &self,
        meta: Self::Metadata,
        delegate_str: String,
        token_account_filter: RpcTokenAccountsFilter,
        config: Option<RpcAccountInfoConfig>,
    ) -> Result<RpcResponse<Vec<RpcKeyedAccount>>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetTokenAccountsByDelegate,
            delegate_str,
            token_account_filter,
            config
        )
    }

    fn get_recent_performance_samples(
        &self,
        meta: Self::Metadata,
        limit: Option<usize>,
    ) -> Result<Vec<RpcPerfSample>> {
        proxy_sol_rpc!(meta.rpc_client, GetRecentPerfomanceSamples, limit)
    }

    fn get_confirmed_blocks_with_limit(
        &self,
        meta: Self::Metadata,
        start_slot: Slot,
        limit: usize,
    ) -> Result<Vec<Slot>> {
        proxy_sol_rpc!(
            meta.rpc_client,
            GetConfirmedBlocksWithLimit,
            start_slot,
            limit
        )
    }
}

#[derive(Debug, structopt::StructOpt)]
struct Args {
    keyfile: Option<String>,
    #[structopt(default_value = "http://127.0.0.1:8899")]
    rpc_address: String,
    #[structopt(default_value = "127.0.0.1:8545")]
    binding_address: SocketAddr,
    #[structopt(default_value = "0xdead")]
    evm_chain_id: U256,
}

use jsonrpc_http_server::jsonrpc_core::*;
use jsonrpc_http_server::*;

use jsonrpc_core::middleware::Middleware;
use jsonrpc_core::middleware::{NoopCallFuture, NoopFuture};

const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];

struct LoggingMiddleware;
impl<M: jsonrpc_core::Metadata> Middleware<M> for LoggingMiddleware {
    type Future = NoopFuture;
    type CallFuture = NoopCallFuture;
    fn on_call<F, X>(
        &self,
        call: Call,
        meta: M,
        next: F,
    ) -> futures::future::Either<Self::CallFuture, X>
    where
        F: Fn(Call, M) -> X + Send + Sync,
        X: futures::Future<Item = Option<Output>> + Send + 'static,
    {
        debug!(target: "jsonrpc_core", "On Request = {:?}", call);
        futures::future::Either::B(next(call, meta))
    }
}

#[paw::main]
fn main(args: Args) -> std::result::Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    let keyfile_path = args
        .keyfile
        .unwrap_or_else(|| solana_cli_config::Config::default().keypair_path);
    let server_path = args.rpc_address;
    let binding_address = args.binding_address;

    let meta = EvmBridge::new(
        args.evm_chain_id,
        &keyfile_path,
        vec![evm::SecretKey::from_slice(&SECRET_KEY_DUMMY).unwrap()],
        server_path,
    );
    let meta = Arc::new(meta);
    let mut io = MetaIoHandler::with_middleware(LoggingMiddleware);

    let sol_rpc = RpcSolProxy;
    io.extend_with(sol_rpc.to_delegate());
    let ether_bridge = BridgeERPCImpl;
    io.extend_with(ether_bridge.to_delegate());
    let ether_basic = BasicERPCProxy;
    io.extend_with(ether_basic.to_delegate());
    let ether_mock = ChainMockERPCProxy;
    io.extend_with(ether_mock.to_delegate());

    info!("Creating server with: {}", binding_address);
    let server =
        ServerBuilder::with_meta_extractor(io, move |_req: &hyper::Request<hyper::Body>| {
            meta.clone()
        })
        .cors(DomainsValidation::AllowOnly(vec![
            AccessControlAllowOrigin::Any,
        ]))
        .threads(4)
        .cors_max_age(86400)
        .start_http(&binding_address)
        .expect("Unable to start EVM bridge server");

    server.wait();
    Ok(())
}

fn send_and_confirm_transactions<T: Signers>(
    rpc_client: &RpcClient,
    mut transactions: Vec<solana::Transaction>,
    signer_keys: &T,
) -> StdResult<(), anyhow::Error> {
    const SEND_RETRIES: usize = 5;
    const STATUS_RETRIES: usize = 15;

    for _ in 0..SEND_RETRIES {
        // Send all transactions
        let mut transactions_signatures = transactions
            .drain(..)
            .map(|transaction| {
                if cfg!(not(test)) {
                    // Delay ~1 tick between write transactions in an attempt to reduce AccountInUse errors
                    // when all the write transactions modify the same program account (eg, deploying a
                    // new program)
                    sleep(Duration::from_millis(1000 / DEFAULT_TICKS_PER_SECOND));
                }

                debug!("Sending {:?}", transaction.signatures);

                let signature = rpc_client
                    .send_transaction_with_config(
                        &transaction,
                        RpcSendTransactionConfig {
                            skip_preflight: true, // NOTE: was true
                            ..RpcSendTransactionConfig::default()
                        },
                    )
                    .map_err(|e| error!("Send transaction error: {:?}", e))
                    .ok();

                (transaction, signature)
            })
            .collect::<Vec<_>>();

        for _ in 0..STATUS_RETRIES {
            // Collect statuses for all the transactions, drop those that are confirmed

            if cfg!(not(test)) {
                // Retry twice a second
                sleep(Duration::from_millis(500));
            }

            transactions_signatures.retain(|(_transaction, signature)| {
                let tx_status = signature
                    .and_then(|signature| rpc_client.get_signature_statuses(&[signature]).ok())
                    .and_then(|RpcResponse { mut value, .. }| value.remove(0));

                // Remove confirmed
                if let Some(TransactionStatus {
                    confirmations: Some(confirmations),
                    ..
                }) = tx_status
                {
                    confirmations == 0 // retain unconfirmed
                } else {
                    true
                }
            });

            if transactions_signatures.is_empty() {
                return Ok(());
            }
        }

        // Re-sign any failed transactions with a new blockhash and retry
        let (blockhash, _) = rpc_client
            .get_new_blockhash(&transactions_signatures[0].0.message().recent_blockhash)?;

        for (mut transaction, _) in transactions_signatures {
            transaction.try_sign(signer_keys, blockhash)?;
            debug!("Resending {:?}", transaction);
            transactions.push(transaction);
        }
    }
    Err(anyhow::Error::msg("Transactions failed"))
}

fn deploy_big_tx(
    rpc_client: &RpcClient,
    payer: &solana_sdk::signature::Keypair,
    tx: &evm::Transaction,
) -> EvmResult<()> {
    let payer_pubkey = payer.pubkey();

    let storage = solana_sdk::signature::Keypair::new();
    let storage_pubkey = storage.pubkey();

    let signers = [payer, &storage];

    debug!("Create new storage {} for EVM tx {:?}", storage_pubkey, tx);

    let tx_bytes = bincode::serialize(&tx).as_proxy_error()?;
    debug!(
        "Storage {} : tx bytes size = {}, chunks crc = {:#x}",
        storage_pubkey,
        tx_bytes.len(),
        TxChunks::new(tx_bytes.as_slice()).crc(),
    );

    let balance = rpc_client
        .get_minimum_balance_for_rent_exemption(tx_bytes.len())
        .as_proxy_error()?;

    let (blockhash, _, _) = rpc_client
        .get_recent_blockhash_with_commitment(CommitmentConfig::max())
        .as_proxy_error()?
        .value;

    let create_storage_ix = system_instruction::create_account(
        &payer_pubkey,
        &storage_pubkey,
        balance,
        tx_bytes.len() as u64,
        &solana_evm_loader_program::ID,
    );

    let allocate_storage_ix =
        solana_evm_loader_program::big_tx_allocate(&storage_pubkey, tx_bytes.len());

    let create_and_allocate_tx = solana::Transaction::new_signed_with_payer(
        &[create_storage_ix, allocate_storage_ix],
        Some(&payer_pubkey),
        &signers,
        blockhash,
    );

    debug!(
        "Create and allocate tx signatures = {:?}",
        create_and_allocate_tx.signatures
    );

    rpc_client
        .send_and_confirm_transaction(&create_and_allocate_tx)
        .map(|signature| {
            debug!(
                "Create and allocate {} tx was done, signature = {:?}",
                storage_pubkey, signature
            )
        })
        .map_err(|e| {
            error!("Error create and allocate {} tx: {:?}", storage_pubkey, e);
            e
        })
        .as_proxy_error()?;

    let (blockhash, _) = rpc_client.get_new_blockhash(&blockhash).as_proxy_error()?;

    let write_data_txs: Vec<solana::Transaction> = tx_bytes
        // TODO: encapsulate
        .chunks(evm_state::TX_MTU)
        .enumerate()
        .map(|(i, chunk)| {
            solana_evm_loader_program::big_tx_write(
                &storage_pubkey,
                (i * evm_state::TX_MTU) as u64,
                chunk.to_vec(),
            )
        })
        .map(|instruction| {
            solana::Transaction::new_signed_with_payer(
                &[instruction],
                Some(&payer_pubkey),
                &signers,
                blockhash,
            )
        })
        .collect();

    debug!("Write data txs: {:?}", write_data_txs);

    send_and_confirm_transactions(&rpc_client, write_data_txs, &signers)
        .map(|_| debug!("All write txs for storage {} was done", storage_pubkey))
        .map_err(|e| {
            error!("Error on write data to storage {}: {:?}", storage_pubkey, e);
            e
        })
        .as_proxy_error()?;

    let (blockhash, _, _) = rpc_client
        .get_recent_blockhash_with_commitment(CommitmentConfig::recent())
        .as_proxy_error()?
        .value;

    let execute_tx = solana::Transaction::new_signed_with_payer(
        &[solana_evm_loader_program::big_tx_execute(&storage_pubkey)],
        Some(&payer_pubkey),
        &signers,
        blockhash,
    );

    debug!("Execute EVM transaction at storage {} ...", storage_pubkey);

    let rpc_send_cfg = RpcSendTransactionConfig {
        skip_preflight: false,
        preflight_commitment: Some(CommitmentLevel::Recent),
        ..Default::default()
    };

    rpc_client
        .send_transaction_with_config(&execute_tx, rpc_send_cfg)
        .map(|signature| {
            debug!(
                "Execute EVM tx at {} was done, signature = {:?}",
                storage_pubkey, signature
            )
        })
        .map_err(|e| {
            error!("Execute EVM tx at {} failed: {:?}", storage_pubkey, e);
            e
        })
        .as_proxy_error()?;

    // TODO: here we can transfer back lamports and delete storage

    Ok(())
}

trait AsProxyRpcError<T> {
    fn as_proxy_error(self) -> EvmResult<T>;
}

impl<T, Err> AsProxyRpcError<T> for StdResult<T, Err>
where
    anyhow::Error: From<Err>,
{
    fn as_proxy_error(self) -> EvmResult<T> {
        self.map_err(anyhow::Error::from)
            .with_context(|| ProxyRpcError {})
    }
}

// impl<T> AsProxyRpcError<T> for StdResult<T, anyhow::Error> {
//     fn as_proxy_error(self) -> EvmResult<T> {
//         self.with_context(|| ProxyRpcError {})
//     }
// }
