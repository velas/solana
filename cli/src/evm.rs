use std::{
    convert::Infallible,
    fs,
    fs::File,
    io,
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

use anyhow::anyhow;
use clap::{value_t_or_exit, App, AppSettings, Arg, ArgGroup, ArgMatches, SubCommand};
use log::*;
use solana_clap_utils::offline::{
    blockhash_arg, sign_only_arg, DUMP_TRANSACTION_MESSAGE, SIGN_ONLY_ARG,
};
use solana_client::blockhash_query::BlockhashQuery;
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    message::Message,
    native_token::{lamports_to_sol, LAMPORTS_PER_VLX},
    pubkey::Pubkey,
    system_instruction, system_program,
    transaction::Transaction,
};

use crate::cli::{CliCommand, CliCommandInfo, CliConfig, CliError, ProcessResult};

use crate::checks::check_unique_pubkeys;
use evm_gas_station::instruction::TxFilter;
use evm_rpc::Hex;
use evm_state::{self as evm, FromKey};
use solana_clap_utils::input_parsers::signer_of;
use solana_clap_utils::input_validators::{is_pubkey, is_valid_signer};
use solana_clap_utils::keypair::{DefaultSigner, SignerIndex};
use solana_client::rpc_response::Response;
use solana_cli_output::{return_signers_with_config, ReturnSignersConfig};
use solana_evm_loader_program::{instructions::FeePayerType, scope::evm::gweis_to_lamports};
use solana_remote_wallet::remote_wallet::RemoteWalletManager;

const SECRET_KEY_DUMMY: [u8; 32] = [1; 32];

pub trait EvmSubCommands {
    fn evm_subcommands(self) -> Self;
}

impl EvmSubCommands for App<'_, '_> {
    fn evm_subcommands(self) -> Self {
        self.subcommand(
            SubCommand::with_name("evm")
                .about("EVM utils")
                .setting(AppSettings::SubcommandRequiredElseHelp)

                .subcommand(
                    SubCommand::with_name("get-evm-balance")
                        .about("Get EVM balance")
                        .display_order(1)
                        .arg(Arg::with_name("address")
                             .takes_value(true)
                             .long("address"))
                        .arg(Arg::with_name("secret_key")
                             .takes_value(true)
                             .long("secret-key"))
                        .group(ArgGroup::with_name("key_source")
                               .args(&["secret_key", "address"])
                               .required(true)))

                .subcommand(
                    SubCommand::with_name("transfer-to-evm")
                        .about("Transfer Native chain token to EVM world")
                        .display_order(2)
                        // TODO: Address can be optional, just use signer / keypair
                        .arg(Arg::with_name("evm_address")
                             .index(1)
                             .takes_value(true)
                             .value_name("EVM_ADDRESS")
                             .help("Receiver address in EVM"))
                        .arg(Arg::with_name("amount")
                             .index(2)
                             .takes_value(true)
                             .value_name("AMOUNT")
                             .help("Amount in VLX"))
                        .arg(Arg::with_name("lamports")
                             .long("lamports")
                             .help("Amount in lamports")))
                        .arg(
                            Arg::with_name("no_wait")
                                .long("no-wait")
                                .takes_value(false)
                                .help("Return signature immediately after submitting the transaction, instead of waiting for confirmations"),
                        )
                        .arg(blockhash_arg())
                        .arg(sign_only_arg())

                .subcommand(
                    SubCommand::with_name("create-gas-station-payer")
                        .about("Create payer account for gas station program")
                        .display_order(3)
                        .arg(Arg::with_name("payer_storage_account")
                                .index(1)
                                .value_name("ACCOUNT_KEYPAIR")
                                .takes_value(true)
                                .required(true)
                                .validator(is_valid_signer)
                                .help("Keypair of the payer storage account"))
                        .arg(Arg::with_name("gas-station-key")
                            .index(2)
                            .takes_value(true)
                            .required(true)
                            .value_name("PROGRAM ID")
                            .help("Public key of gas station program"))
                        .arg(Arg::with_name("lamports")
                            .index(3)
                            .takes_value(true)
                            .required(true)
                            .value_name("AMOUNT")
                            .help("Amount in lamports to transfer to created account"))
                        .arg(Arg::with_name("filters_path")
                            .index(4)
                            .takes_value(true)
                            .required(true)
                            .value_name("PATH")
                            .help("Path to json file with filter to store in payer storage"))
                        .arg(Arg::with_name("payer_owner")
                            .index(5)
                            .value_name("ACCOUNT_KEYPAIR")
                            .takes_value(true)
                            .validator(is_valid_signer)
                            .help("Keypair of the owner account"))
                )
                .subcommand(
                    SubCommand::with_name("update-gas-station-payer")
                        .about("Update filters in payer account for gas station program")
                        .display_order(4)
                        .arg(
                            Arg::with_name("payer_storage_pubkey")
                                .index(1)
                                .value_name("PUBKEY")
                                .takes_value(true)
                                .required(true)
                                .validator(is_pubkey)
                                .help("The pubkey of the payer storage account to update"))
                        .arg(Arg::with_name("gas-station-key")
                            .index(2)
                            .takes_value(true)
                            .required(true)
                            .value_name("PROGRAM ID")
                            .help("Public key of gas station program"))
                        .arg(Arg::with_name("filters_path")
                            .index(3)
                            .takes_value(true)
                            .required(true)
                            .value_name("PATH")
                            .help("Path to json file with filter to store in payer storage"))
                )


            // Hidden commands

                .subcommand(
                    SubCommand::with_name("send-raw-tx")
                        .setting(AppSettings::Hidden)
                        .about("Broadcast raw EVM transaction")
                        .arg(Arg::with_name("raw_tx")
                             .takes_value(true)
                             .value_name("RAW_TX")
                             .help("A path to a file where raw transaction is stored in bincode encoding")))

                .subcommand(
                    SubCommand::with_name("create-dummy")
                        .setting(AppSettings::Hidden)
                        .about("Create dummy \"CREATE\" transaction")
                        .arg(Arg::with_name("tx_file")
                             .takes_value(true)
                             .conflicts_with("contract_code"))
                        .arg(Arg::with_name("contract_code")
                             .takes_value(true)
                             .short("c")
                             .long("code")
                             .conflicts_with("tx_file")))

                .subcommand(
                    SubCommand::with_name("call_dummy")
                        .setting(AppSettings::Hidden)
                        .about("Create dummy \"CALL\" transaction")
                        .arg(Arg::with_name("tx_file")
                             .takes_value(true)
                             .conflicts_with("contract_code"))
                        .arg(Arg::with_name("contract_code")
                             .takes_value(true)
                             .short("a")
                             .long("abi")
                             .conflicts_with("tx_file")))

                .subcommand(
                    SubCommand::with_name("parse_array")
                        .setting(AppSettings::Hidden)
                        .about("Parse binary array as HEX/UTF8")
                        .arg(Arg::with_name("array")
                             .takes_value(true)
                             .required(true)))

                .subcommand(
                    SubCommand::with_name("find_block_header")
                        .setting(AppSettings::Hidden)
                        .about("") // TODO(hrls): transfer comment
                        .arg(Arg::with_name("expected_block_hash")
                             .takes_value(true)
                             .long("expected-blockhash"))
                        .arg(Arg::with_name("range")
                             .takes_value(true)
                             .long("blocks-range"))
                        .arg(Arg::with_name("file")
                             .takes_value(true)
                             .long("file")
                             .default_value("-")))

                .subcommand(
                    SubCommand::with_name("print_evm_address")
                        .setting(AppSettings::Hidden)
                        .about("Print EVM address")
                        .arg(Arg::with_name("secret_key")
                             .takes_value(true)
                             .value_name("SECRET_KEY")
                             .help("HEX representated private key")))
        )
    }
}

#[derive(Debug, PartialEq)]
pub enum EvmCliCommand {
    GetEvmBalance {
        identity: Identity,
    },

    TransferToEvm {
        address: evm::Address,
        amount: u64,
        sign_only: bool,
        dump_transaction_message: bool,
        no_wait: bool,
        blockhash_query: BlockhashQuery,
    },

    CreateGasStationPayer {
        payer_storage_signer_index: SignerIndex,
        payer_owner_signer_index: SignerIndex,
        gas_station_key: Pubkey,
        lamports: u64,
        filters: PathBuf,
    },

    UpdateGasStationPayer {
        payer_storage_pubkey: Pubkey,
        gas_station_key: Pubkey,
        filters: PathBuf,
    },

    // Hidden commands
    SendRawTx {
        raw_tx: PathBuf,
    },

    CreateDummy {
        tx_file: PathBuf,
        contract_code: Option<Vec<u8>>,
    },
    CallDummy {
        tx_file: PathBuf,
        create_tx: PathBuf,
        abi: Option<Vec<u8>>,
    },

    PrintEvmAddress {
        secret_key: evm::SecretKey,
    },

    ParseArray {
        array: String,
    },

    FindBlockHeader {
        expected_block_hash: evm::H256,
        range: u64,
        file: FileKind,
    },
}

impl EvmCliCommand {
    pub fn process_with(&self, rpc_client: &RpcClient, config: &CliConfig) -> ProcessResult {
        match self {
            Self::GetEvmBalance { identity } => {
                let address = identity.address();
                get_evm_balance(rpc_client, address)?;
                Ok("Ok".to_string())
            }
            Self::TransferToEvm {
                address,
                amount,
                sign_only,
                no_wait,
                dump_transaction_message,
                ref blockhash_query,
            } => transfer(
                rpc_client,
                config,
                *address,
                *amount,
                *sign_only,
                *dump_transaction_message,
                *no_wait,
                blockhash_query,
            ),
            Self::CreateGasStationPayer {
                payer_storage_signer_index,
                payer_owner_signer_index,
                gas_station_key,
                lamports,
                filters,
            } => {
                create_gas_station_payer(
                    rpc_client,
                    config,
                    *payer_storage_signer_index,
                    *payer_owner_signer_index,
                    *gas_station_key,
                    *lamports,
                    filters,
                )?;
                Ok("Ok".to_string())
            }
            Self::UpdateGasStationPayer {
                payer_storage_pubkey,
                gas_station_key,
                filters,
            } => {
                update_gas_station_payer(
                    rpc_client,
                    config,
                    *payer_storage_pubkey,
                    *gas_station_key,
                    filters,
                )?;
                Ok("Ok".to_string())
            }
            // Hidden commands
            Self::SendRawTx { raw_tx } => {
                send_raw_tx(rpc_client, config, raw_tx)?;
                Ok("Ok".to_string())
            }
            Self::CreateDummy {
                tx_file,
                contract_code,
            } => {
                create_dummy(tx_file, contract_code.as_ref().map(Vec::as_slice))?;
                Ok("Ok".to_string())
            }
            Self::CallDummy {
                tx_file,
                create_tx,
                abi,
            } => {
                call_dummy(tx_file, create_tx, abi.as_ref().map(Vec::as_slice))?;
                Ok("Ok".to_string())
            }
            Self::PrintEvmAddress { secret_key } => {
                Ok(format!("EVM Address: {:?}", secret_key.to_address()))
            }
            Self::ParseArray { array } => {
                let bytes: Vec<u8> = serde_json::from_str(array)?;
                Ok(format!(
                    "Resulting data hex = {}\nResulting data utf8 = {}",
                    hex::encode(&bytes),
                    String::from_utf8_lossy(&bytes)
                ))
            }
            Self::FindBlockHeader {
                expected_block_hash,
                range,
                file,
            } => {
                find_block_header(rpc_client, *expected_block_hash, *range, file)?;
                Ok("Ok".to_string())
            }
        }
    }
}

fn get_evm_balance(rpc_client: &RpcClient, address: evm::H160) -> anyhow::Result<()> {
    let balance = rpc_client.get_evm_balance(&address)?;
    let (lamports, _dust) = gweis_to_lamports(balance);
    let vlx = lamports_to_sol(lamports);

    println!(
        "EVM address: {:?}, balance {} ({} in hex)",
        address,
        vlx,
        Hex(balance)
    );
    Ok(())
}

fn transfer(
    rpc_client: &RpcClient,
    config: &CliConfig,
    evm_address: evm::Address,
    amount: u64,
    sign_only: bool,
    dump_transaction_message: bool,
    no_wait: bool,
    blockhash_query: &BlockhashQuery,
) -> ProcessResult {
    assert_eq!(config.signers.len(), 1, "Expected exact one signer");
    let from = config
        .signers
        .first()
        .ok_or_else(|| anyhow!("No signers found"))?;

    let ixs =
        solana_evm_loader_program::transfer_native_to_evm_ixs(from.pubkey(), amount, evm_address);

    let message = Message::new(&ixs, Some(&from.pubkey()));
    let mut create_account_tx = Transaction::new_unsigned(message);

    let recent_blockhash = blockhash_query.get_blockhash(rpc_client, config.commitment)?;

    if sign_only {
        create_account_tx.try_partial_sign(&config.signers, recent_blockhash)?;
        return_signers_with_config(
            &create_account_tx,
            &config.output_format,
            &ReturnSignersConfig {
                dump_transaction_message,
            },
        )
    } else {
        create_account_tx.sign(&config.signers, recent_blockhash);

        let signature = if no_wait {
            rpc_client.send_transaction(&create_account_tx)?
        } else {
            rpc_client.send_and_confirm_transaction_with_spinner_and_config(
                &create_account_tx,
                CommitmentConfig::default(),
                Default::default(),
            )?
        };
        Ok(format!(
            "Transaction signature = {}",
            signature
        ))
    }
}

fn create_gas_station_payer<P: AsRef<Path>>(
    rpc_client: &RpcClient,
    config: &CliConfig,
    payer_storage_signer_index: SignerIndex,
    payer_owner_signer_index: SignerIndex,
    gas_station_key: Pubkey,
    transfer_amount: u64,
    filters: P,
) -> anyhow::Result<()> {
    let cli_pubkey = config.signers[0].pubkey();
    let payer_storage_pubkey = config.signers[payer_storage_signer_index].pubkey();
    let payer_owner_pubkey = config.signers[payer_owner_signer_index].pubkey();
    check_unique_pubkeys(
        (&payer_storage_pubkey, "payer_storage_pubkey".to_string()),
        (&payer_owner_pubkey, "payer_owner_pubkey".to_string()),
    )?;

    let file = File::open(filters)
        .map_err(|e| custom_error(format!("Unable to open filters file: {:?}", e)))?;
    let filters: Vec<TxFilter> = serde_json::from_reader(file)
        .map_err(|e| custom_error(format!("Unable to decode json: {:?}", e)))?;

    let mut instructions = vec![];
    if let Response { value: None, .. } =
        rpc_client.get_account_with_commitment(&payer_owner_pubkey, CommitmentConfig::default())?
    {
        let create_owner_ix = system_instruction::create_account(
            &cli_pubkey,
            &payer_owner_pubkey,
            rpc_client.get_minimum_balance_for_rent_exemption(0)?,
            0,
            &system_program::id(),
        );
        info!("Add instruction to create owner: {}", payer_owner_pubkey);
        instructions.push(create_owner_ix);
    }
    let state_size = evm_gas_station::get_state_size(&filters);
    let minimum_balance = rpc_client.get_minimum_balance_for_rent_exemption(state_size)?;
    let create_storage_ix = evm_gas_station::create_storage_account(
        &cli_pubkey,
        &payer_storage_pubkey,
        minimum_balance,
        &filters,
        &gas_station_key,
    );
    info!("Add instruction to create storage: {}", payer_storage_pubkey);
    instructions.push(create_storage_ix);
    let register_payer_ix = evm_gas_station::register_payer(
        gas_station_key,
        cli_pubkey,
        payer_storage_pubkey,
        payer_owner_pubkey,
        transfer_amount,
        filters,
    );
    info!(
        "Add instruction to register payer: gas-station={}, signer={}, storage={}, owner={}",
        gas_station_key, cli_pubkey, payer_storage_pubkey, payer_owner_pubkey
    );
    instructions.push(register_payer_ix);
    let message = Message::new(&instructions, Some(&cli_pubkey));
    let latest_blockhash = rpc_client.get_latest_blockhash()?;

    let mut tx = Transaction::new_unsigned(message);
    tx.try_sign(&config.signers, latest_blockhash)?;
    let signature = rpc_client.send_and_confirm_transaction_with_spinner(&tx)?;
    println!("Transaction signature = {}", signature);
    Ok(())
}

fn update_gas_station_payer<P: AsRef<Path>>(
    rpc_client: &RpcClient,
    config: &CliConfig,
    payer_storage_pubkey: Pubkey,
    gas_station_key: Pubkey,
    filters: P,
) -> anyhow::Result<()> {
    let file = File::open(filters)
        .map_err(|e| custom_error(format!("Unable to open filters file: {:?}", e)))?;
    let filters: Vec<TxFilter> = serde_json::from_reader(file)
        .map_err(|e| custom_error(format!("Unable to decode json: {:?}", e)))?;

    let sender_pubkey = config.signers[0].pubkey();
    let ix = evm_gas_station::update_filters(
        gas_station_key,
        sender_pubkey,
        payer_storage_pubkey,
        filters,
    );
    let message = Message::new(&[ix], Some(&sender_pubkey));
    let latest_blockhash = rpc_client.get_latest_blockhash()?;

    let mut tx = Transaction::new_unsigned(message);
    tx.try_sign(&config.signers, latest_blockhash)?;
    let signature = rpc_client.send_and_confirm_transaction_with_spinner(&tx)?;
    println!("Transaction signature = {}", signature);
    Ok(())
}

fn find_block_header(
    rpc_client: &RpcClient,
    expected_block_hash: evm::H256,
    range: u64,
    file: &FileKind,
) -> anyhow::Result<()> {
    println!("Reading block header from {}", file.description());
    let r = file.reader()?;
    let block: evm_rpc::RPCBlock = serde_json::from_reader(r)?;
    let mut block: evm_state::BlockHeader = block.to_native_block(Default::default());
    debug!("Readed block = {:?}", block);

    let native_slot = block.native_chain_slot;
    for slot in native_slot - range..native_slot + range {
        let native_block = match rpc_client.get_block(slot) {
            Ok(native_block) => native_block,
            Err(_) => {
                debug!("Skiped slot = {:?}, Cannot request blockhash", slot);
                continue;
            }
        };

        let hash = solana_sdk::hash::Hash::from_str(&native_block.blockhash)?;
        let hash = evm::H256::from_slice(&hash.to_bytes());
        block.native_chain_hash = hash;
        block.native_chain_slot = slot;
        debug!("Produced block = {:?}, hash = {:?}", block, block.hash());

        if block.hash() == expected_block_hash {
            println!("Block slot found, slot = {}", slot);
            return Ok(());
        }
    }

    anyhow::bail!("Block slot not found.");
}

fn send_raw_tx<P: AsRef<Path>>(
    rpc_client: &RpcClient,
    config: &CliConfig,
    raw_tx: P,
) -> anyhow::Result<()> {
    assert_eq!(config.signers.len(), 1, "Expected exact one signer");
    let signer = config
        .signers
        .first()
        .ok_or_else(|| anyhow!("No signers found"))?;

    let bytes = fs::read(raw_tx)?;
    let tx: evm::Transaction = solana_sdk::program_utils::limited_deserialize(&bytes)?;
    debug!("loaded tx: {:?}", tx);

    let ix = solana_evm_loader_program::send_raw_tx(signer.pubkey(), tx, None, FeePayerType::Evm);
    let msg = Message::new(&[ix], Some(&signer.pubkey()));
    let mut tx = Transaction::new_unsigned(msg);

    let (blockhash, _last_height) =
        rpc_client.get_latest_blockhash_with_commitment(CommitmentConfig::default())?;
    tx.sign(&config.signers, blockhash);

    debug!("sending tx: {:?}", tx);
    let signature = rpc_client.send_and_confirm_transaction_with_spinner_and_config(
        &tx,
        CommitmentConfig::default(),
        Default::default(),
    )?;
    println!("signature = {:?}", signature);
    Ok(())
}

fn create_dummy(tx_file: impl AsRef<Path>, contract_code: Option<&[u8]>) -> anyhow::Result<()> {
    let contract_code =
        hex::decode(contract_code.unwrap_or_else(|| evm_state::HELLO_WORLD_CODE.as_bytes()))?
            .to_vec();

    let create_tx = evm::UnsignedTransaction {
        nonce: 0.into(),
        gas_price: 0.into(),
        gas_limit: 300_000.into(),
        action: evm::TransactionAction::Create,
        value: 0.into(),
        input: contract_code,
    };

    let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY)?;
    let create_tx = create_tx.sign(&secret_key, None);

    let data = bincode::serialize(&create_tx)?;
    fs::write(tx_file, data)?;

    Ok(())
}

fn call_dummy(
    tx_file: impl AsRef<Path>,
    create_tx: impl AsRef<Path>,
    abi: Option<&[u8]>,
) -> anyhow::Result<()> {
    let create_tx = fs::read(create_tx)?;
    let evm_tx: evm::Transaction = solana_sdk::program_utils::limited_deserialize(&create_tx)?;
    let tx_address = evm_tx.address()?;
    let abi = hex::decode(abi.unwrap_or_else(|| evm_state::HELLO_WORLD_ABI.as_bytes()))?.to_vec();

    let call_tx = evm::UnsignedTransaction {
        nonce: 0.into(),
        gas_price: 0.into(),
        gas_limit: 300_000.into(),
        action: evm::TransactionAction::Call(tx_address),
        value: 0.into(),
        input: abi,
    };

    let secret_key = evm::SecretKey::from_slice(&SECRET_KEY_DUMMY)?;
    let call_tx = call_tx.sign(&secret_key, None);

    let data = bincode::serialize(&call_tx)?;
    fs::write(tx_file, data)?;

    Ok(())
}

pub fn parse_evm_subcommand(
    matches: &ArgMatches<'_>,
    default_signer: &DefaultSigner,
    wallet_manager: &mut Option<Arc<RemoteWalletManager>>,
) -> Result<CliCommandInfo, CliError> {
    let mut signers = vec![];
    let subcommand = match matches.subcommand() {
        ("get-evm-balance", Some(matches)) => {
            assert!(matches.is_present("key_source"));
            if let Some(address) = matches
                .value_of("address")
                .map(str::parse)
                .transpose()
                .map_err(|e| custom_error(format!("Unable to parse address: {:?}", e)))?
            {
                let identity = Identity::Address(address);
                EvmCliCommand::GetEvmBalance { identity }
            } else if let Some(secret_key) = matches
                .value_of("secret_key")
                .map(str::parse::<evm::SecretKey>)
                .transpose()
                .map_err(|e| custom_error(format!("Unable to parse secret key: {:?}", e)))?
            {
                let identity = Identity::SecretKey(secret_key);
                EvmCliCommand::GetEvmBalance { identity }
            } else {
                // TODO: probably we can imply derived address
                panic!("Some required args are missed or not matched correctly");
            }
        }
        ("transfer-to-evm", Some(matches)) => {
            let address = value_t_or_exit!(matches, "evm_address", evm::Address);
            let mut amount = value_t_or_exit!(matches, "amount", u64);
            if !matches.is_present("lamports") {
                amount *= LAMPORTS_PER_VLX;
            }
            let sign_only = matches.is_present(SIGN_ONLY_ARG.name);
            let dump_transaction_message = matches.is_present(DUMP_TRANSACTION_MESSAGE.name);
            let no_wait = matches.is_present("no_wait");
            let blockhash_query = BlockhashQuery::new_from_matches(matches);

            EvmCliCommand::TransferToEvm {
                address,
                amount,
                sign_only,
                dump_transaction_message,
                no_wait,
                blockhash_query,
            }
        }
        ("create-gas-station-payer", Some(matches)) => {
            signers = vec![default_signer.signer_from_path(matches, wallet_manager)?];
            let (payer_storage_signer, _address) =
                signer_of(matches, "payer_storage_account", wallet_manager)?;
            let (payer_owner_signer, _address) = signer_of(matches, "payer_owner", wallet_manager)?;
            let payer_storage_signer_index = payer_storage_signer
                .map(|signer| {
                    signers.push(signer);
                    1
                })
                .unwrap();
            let payer_owner_signer_index = payer_owner_signer
                .map(|signer| {
                    signers.push(signer);
                    2
                })
                .unwrap_or(0);

            let gas_station_key = value_t_or_exit!(matches, "gas-station-key", Pubkey);
            let lamports = value_t_or_exit!(matches, "lamports", u64);
            let filters = value_t_or_exit!(matches, "filters_path", PathBuf);

            EvmCliCommand::CreateGasStationPayer {
                payer_storage_signer_index,
                payer_owner_signer_index,
                gas_station_key,
                lamports,
                filters,
            }
        }
        ("update-gas-station-payer", Some(matches)) => {
            let payer_storage_pubkey = value_t_or_exit!(matches, "payer_storage_pubkey", Pubkey);
            let gas_station_key = value_t_or_exit!(matches, "gas-station-key", Pubkey);
            let filters = value_t_or_exit!(matches, "filters_path", PathBuf);

            EvmCliCommand::UpdateGasStationPayer {
                payer_storage_pubkey,
                gas_station_key,
                filters,
            }
        }
        ("send-raw-tx", Some(matches)) => {
            let raw_tx = value_t_or_exit!(matches, "raw_tx", PathBuf);
            EvmCliCommand::SendRawTx { raw_tx }
        }
        ("create-dummy", Some(matches)) => {
            let tx_file = value_t_or_exit!(matches, "tx_file", PathBuf);
            let contract_code = matches
                .value_of("contract_code")
                .map(|s| s.as_bytes().to_vec());

            EvmCliCommand::CreateDummy {
                tx_file,
                contract_code,
            }
        }
        ("find-block-header", Some(matches)) => {
            let expected_block_hash = value_t_or_exit!(matches, "expected_block_hash", evm::H256);
            let range = value_t_or_exit!(matches, "range", u64);
            let file = value_t_or_exit!(matches, "file", FileKind);
            EvmCliCommand::FindBlockHeader {
                expected_block_hash,
                range,
                file,
            }
        }
        ("print-evm-address", Some(matches)) => {
            let secret_key = value_t_or_exit!(matches, "secret_key", evm::SecretKey);
            EvmCliCommand::PrintEvmAddress { secret_key }
        }
        _ => panic!("Unhandled matches: {:?}", matches),
    };

    let command = CliCommand::Evm(subcommand);
    Ok(CliCommandInfo { command, signers })
}

/// Input file, or dash for stdin
#[derive(Debug, PartialEq)]
pub enum FileKind {
    Stdin,
    File(PathBuf),
}

impl FileKind {
    fn description(&self) -> &str {
        match self {
            Self::Stdin => "stdin",
            Self::File(path) => path
                .as_path()
                .to_str()
                .expect("Only valid unicode file names are supported"),
        }
    }

    fn reader(&self) -> io::Result<Box<dyn io::Read>> {
        Ok(match self {
            Self::Stdin => Box::new(io::stdin()),
            Self::File(path) => Box::new(fs::File::open(path)?),
        })
    }
}

impl FromStr for FileKind {
    type Err = Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let v = match s {
            "-" => Self::Stdin,
            _ => Self::File(PathBuf::from_str(s)?),
        };
        Ok(v)
    }
}

#[derive(Debug, PartialEq)]
pub enum Identity {
    Address(evm::Address),
    SecretKey(evm::SecretKey),
}

impl Identity {
    fn address(&self) -> evm::Address {
        match self {
            Self::Address(address) => *address,
            Self::SecretKey(secret_key) => secret_key.to_address(),
        }
    }
}

fn custom_error(description: String) -> CliError {
    CliError::DynamicProgramError(description)
}
