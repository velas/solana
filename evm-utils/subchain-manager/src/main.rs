use {
    evm_rpc::{Bytes, FormatHex},
    evm_state::U256,
    genesis_json::ChainID,
    inquire::{validator::Validation, Select},
    interactive_clap::{ResultFromCli, ToCliArgs},
    multizip::zip3,
    std::{cell::Cell, collections::BTreeMap, error::Error, fmt::Display, str::FromStr},
    strum::{EnumDiscriminants, EnumIter, EnumMessage, IntoEnumIterator},
};

mod genesis_json;
mod implementation;

// Choose a name for the chain:
// Pick a name for the token:
// Select a Chain ID (should be unique, and start with 0x56): 0x56_
// Hardfork version (default: istanbul):

// Minting address:
// Balance (in $NAME$):
// One more minting address (empty if skip):

// Do you want to add optional fields? (y/n)
// Select a token symbol:
// RPC URL: ?

#[derive(Debug, Clone)]
pub struct InputContext {
    skip_optional_args: Cell<bool>,
}

impl From<()> for InputContext {
    fn from(_value: ()) -> Self {
        InputContext {
            skip_optional_args: false.into(),
        }
    }
}

#[derive(Debug, Clone, interactive_clap::InteractiveClap, serde::Serialize, serde::Deserialize)]
#[interactive_clap(input_context = InputContext)]
pub struct Config {
    /// Choose a name for the chain:
    #[interactive_clap(long)]
    network_name: String,

    /// Pick a name for the token:
    #[interactive_clap(long)]
    token_name: String,

    /// Select a Chain ID (should be unique, and start with 0x56): 0x56_
    #[interactive_clap(skip_default_input_arg)]
    chain_id: ChainID,

    /// Hardfork version (default: istanbul):
    // #[interactive_clap(skip_default_input_arg)]
    #[interactive_clap(long)]
    #[interactive_clap(value_enum)]
    #[interactive_clap(skip_default_input_arg)]
    hardfork: Hardfork,

    // skip serialization
    /// Store config in file:
    #[serde(skip)]
    #[interactive_clap(long)]
    config_path: String,

    #[interactive_clap(flatten)]
    #[interactive_clap(skip_default_input_arg)]
    minting_addresses: MintingAddresses,

    // Optional fields:
    /// Select a token symbol:
    #[interactive_clap(long)]
    #[interactive_clap(skip_default_input_arg)]
    token_symbol: String,

    /// Provide RPC URL for future tooling:
    #[interactive_clap(long)]
    #[interactive_clap(skip_default_input_arg)]
    rpc_url: String,
}

impl Config {
    fn input_token_symbol(context: &InputContext) -> color_eyre::eyre::Result<Option<String>> {
        let skip_optional_args = !inquire::Confirm::new("Do you want to add optional fields?")
            .with_default(false)
            .prompt()?;

        context.skip_optional_args.set(skip_optional_args);
        if skip_optional_args {
            return Ok(None);
        }
        match inquire::Text::new("Select a token symbol:").prompt() {
            Ok(value) => Ok(Some(value)),
            Err(
                inquire::error::InquireError::OperationCanceled
                | inquire::error::InquireError::OperationInterrupted,
            ) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }
    fn input_rpc_url(context: &InputContext) -> color_eyre::eyre::Result<Option<String>> {
        if context.skip_optional_args.get() {
            return Ok(None);
        }
        match inquire::Text::new("RPC URL:").prompt() {
            Ok(value) => Ok(Some(value)),
            Err(
                inquire::error::InquireError::OperationCanceled
                | inquire::error::InquireError::OperationInterrupted,
            ) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }

    fn input_minting_addresses(
        _context: &InputContext,
    ) -> color_eyre::eyre::Result<Option<MintingAddresses>> {
        let mut addresses = vec![];
        let mut balances = vec![];
        let mut codes = vec![];
        // TODO(H): implement storage in allocs
        // let mut storages: Vec<std::collections::BTreeMap<(), ()>> = vec![];

        let mut address: evm_state::H160 =
            match inquire::CustomType::new("Minting address:").prompt() {
                Ok(value) => value,
                Err(
                    inquire::error::InquireError::OperationCanceled
                    | inquire::error::InquireError::OperationInterrupted,
                ) => return Ok(None),
                Err(err) => return Err(err.into()),
            };

        loop {
            let balance: U256 = match inquire::CustomType::new("Balance (wei):").prompt() {
                Ok(value) => value,
                Err(
                    inquire::error::InquireError::OperationCanceled
                    | inquire::error::InquireError::OperationInterrupted,
                ) => break,
                Err(err) => return Err(err.into()),
            };
            let code: Bytes = match inquire::CustomType::new("Code (hex):").prompt() {
                Ok(code) => code,
                Err(
                    inquire::error::InquireError::OperationCanceled
                    | inquire::error::InquireError::OperationInterrupted,
                ) => return Ok(None),
                Err(err) => return Err(err.into()),
            };
            addresses.push(address);
            balances.push(balance);
            codes.push(code);
            let naddress: Option<_> =
                match inquire::Text::new("One more minting address (esc to skip):")
                    .with_validator(
                        |v: &str| -> Result<Validation, Box<dyn Error + Send + Sync>> {
                            if v.is_empty() {
                                return Ok(Validation::Valid);
                            }
                            if !v.starts_with("0x") {
                                return Ok(Validation::Invalid(
                                    "Address should start with 0x".into(),
                                ));
                            }
                            if v.len() != 42 {
                                return Ok(Validation::Invalid(
                                    "Address should be 42 characters long".into(),
                                ));
                            }
                            if !v[2..].chars().all(|c| c.is_digit(16)) {
                                return Ok(Validation::Invalid(
                                    "Address should be a hex number".into(),
                                ));
                            }
                            Ok(Validation::Valid)
                        },
                    )
                    .prompt_skippable()
                {
                    Ok(value) => value,
                    Err(
                        inquire::error::InquireError::OperationCanceled
                        | inquire::error::InquireError::OperationInterrupted,
                    ) => break,
                    Err(err) => return Err(err.into()),
                };
            if naddress.is_none() {
                break;
            }
            let Ok(naddress) = Address::from_hex(&naddress.unwrap()) else {
                break;
            };
            address = naddress;
        }

        Ok(Some(MintingAddresses {
            address: addresses,
            balance: balances,
            code: codes,
        }))
    }

    fn input_chain_id(_context: &InputContext) -> color_eyre::eyre::Result<Option<u64>> {
        // loop {
        match inquire::Text::new("Pick a Chain ID: ")
            .with_initial_value(CHAIN_ID_PREFIX)
            .with_placeholder(&format!("unique hex number, starts with {CHAIN_ID_PREFIX}"))
            .with_validator(
                |v: &str| -> Result<Validation, Box<dyn Error + Send + Sync>> {
                    if !v.starts_with(CHAIN_ID_PREFIX) {
                        return Ok(Validation::Invalid(
                            "Chain ID should start with 0x56".into(),
                        ));
                    }
                    if v.len() < 5 {
                        return Ok(Validation::Invalid(
                            "Chain ID should be at least 3 characters long".into(),
                        ));
                    }
                    if !v[2..].chars().all(|c| c.is_digit(16)) {
                        return Ok(Validation::Invalid(
                            "Chain ID should be a hex number".into(),
                        ));
                    }
                    Ok(Validation::Valid)
                },
            )
            .prompt()
        {
            Ok(value) if value.starts_with(CHAIN_ID_PREFIX) => {
                let value = value.strip_prefix("0x").unwrap();
                match u64::from_str_radix(value, 16) {
                    Ok(chain_id) => Ok(Some(chain_id)),
                    Err(err) => Err(err.into()),
                }
            }
            Ok(_) => Ok(None),
            Err(
                inquire::error::InquireError::OperationCanceled
                | inquire::error::InquireError::OperationInterrupted,
            ) => Ok(None),
            Err(err) => Err(err.into()),
        }
        // }
    }

    fn input_hardfork(_context: &InputContext) -> color_eyre::eyre::Result<Option<Hardfork>> {
        let variants = HardforkDiscriminants::iter().collect::<Vec<_>>();
        let selected = Select::new("Hardfork version:", variants).prompt()?;
        match selected {
            HardforkDiscriminants::Istanbul => Ok(Some(Hardfork::Istanbul)),
        }
    }
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize, clap::Parser)]
pub struct MintingAddresses {
    address: Vec<Address>,
    balance: Vec<Balance>,
    code: Vec<Bytes>,
    // TODO(H): implement storage in allocs
    // storage: Vec<std::collections::BTreeMap<(), ()>>,
}

impl interactive_clap::ToCliArgs for MintingAddresses {
    fn to_cli_args(&self) -> std::collections::VecDeque<String> {
        let mut args = std::collections::VecDeque::new();
        for (address, balance, code) in
            zip3(self.address.iter(), self.balance.iter(), self.code.iter())
        {
            args.push_back("--address".to_string());
            args.push_back(balance.to_string());
            args.push_back("--balance".to_string());
            args.push_back(address.to_string());
            args.push_back("--code".to_string());
            args.push_back(code.to_string());
            // TODO(H): implement storage in allocs
        }

        args
    }
}

impl interactive_clap::ToCli for MintingAddresses {
    type CliVariant = MintingAddresses;
}

type Balance = U256;
type Address = evm_state::Address;

#[derive(Debug, Clone, interactive_clap::InteractiveClap, serde::Serialize, serde::Deserialize)]
pub struct DeployConfig {
    /// Path to config file:
    #[interactive_clap(long)]
    config_file: String,

    /// Velas rpc url:
    #[interactive_clap(long)]
    velas_rpc: String,

    /// Path to keypair:
    #[interactive_clap(long)]
    #[interactive_clap(skip_default_input_arg)]
    keypair_path: String,

    /// Simulate transaction instead of deploying:
    #[interactive_clap(long)]
    dry_run: bool,
}
impl DeployConfig {
    fn input_keypair_path(_context: &()) -> color_eyre::eyre::Result<Option<String>> {
        let default_keypair = if let Some(config) = &*solana_cli_config::CONFIG_FILE {
            let config = solana_cli_config::Config::load(&config)?;
            config.keypair_path
        } else {
            ".config/velas/id.json".to_string()
        };
        match inquire::CustomType::new("Path to keypair:")
            .with_default(default_keypair)
            .prompt()
        {
            Ok(value) => Ok(Some(value)),
            Err(
                inquire::error::InquireError::OperationCanceled
                | inquire::error::InquireError::OperationInterrupted,
            ) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }
}

#[derive(Debug, Clone, interactive_clap::InteractiveClap, serde::Serialize, serde::Deserialize)]
pub struct OnlyFile {
    /// Path to config file:
    #[interactive_clap(long)]
    #[interactive_clap(skip_default_input_arg)]
    config_file: String,
}
impl OnlyFile {
    fn input_config_file(_context: &()) -> color_eyre::eyre::Result<Option<String>> {
        match inquire::Text::new("Path to config file:")
            .with_validator(
                |val: &str| -> Result<Validation, Box<dyn Error + Send + Sync>> {
                    if val.is_empty() {
                        return Ok(Validation::Invalid("Path cannot be empty".into()));
                    }
                    if !std::path::Path::new(val).exists() {
                        return Ok(Validation::Invalid("File does not exist".into()));
                    }
                    Ok(Validation::Valid)
                },
            )
            .prompt()
        {
            Ok(value) => Ok(Some(value)),
            Err(
                inquire::error::InquireError::OperationCanceled
                | inquire::error::InquireError::OperationInterrupted,
            ) => Ok(None),
            Err(err) => Err(err.into()),
        }
    }
}

#[derive(
    Eq,
    PartialEq,
    Debug,
    EnumDiscriminants,
    Clone,
    clap::ValueEnum,
    serde::Serialize,
    serde::Deserialize,
)]
#[strum_discriminants(derive(EnumMessage, EnumIter))]
///
/// Network hardfork version.
///
pub enum Hardfork {
    /// Istanbul hardfork.
    #[strum_discriminants(strum(message = "Istanbul hardfork (currently only available)."))]
    Istanbul,
}

impl Default for Hardfork {
    fn default() -> Self {
        Hardfork::Istanbul
    }
}
impl interactive_clap::ToCli for Hardfork {
    type CliVariant = Hardfork;
}

impl FromStr for Hardfork {
    type Err = Box<dyn Error>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "istanbul" => Ok(Hardfork::Istanbul),
            _ => Err("Unknown hardfork version".into()),
        }
    }
}
impl Display for Hardfork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Hardfork::Istanbul => write!(f, "istanbul"),
        }
    }
}

impl std::fmt::Display for HardforkDiscriminants {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.get_message().unwrap().fmt(f)
    }
}

#[derive(Debug, EnumDiscriminants, Clone, interactive_clap::InteractiveClap)]
#[strum_discriminants(derive(EnumMessage, EnumIter))]
#[derive(serde::Serialize, serde::Deserialize)]
#[interactive_clap(disable_back)]
///
/// This program helps to create and manage subchains.
/// It allows create config for new subchain, that can be later used to deploy subchain, and other infrastrucutre (like bridges and explorers).
///
pub enum SubCommand {
    /// Generate a config for new subchain and store it into file.
    #[strum_discriminants(strum(message = "Generate a new config"))]
    GenerateConfig(Config),

    /// Use 'geth init' genesis and add needed fields.
    #[strum_discriminants(strum(message = "Use 'geth init' genesis and add needed fields"))]
    ImportGetGenesis(OnlyFile),
    /// Deploy a new subchain using config file.
    #[strum_discriminants(strum(message = "Create and deploy new subchain from config"))]
    CreateAndDeploy(DeployConfig),
    /// Get address of subchain account.
    #[strum_discriminants(strum(message = "Get address of subchain account"))]
    GetSubchainAddress(OnlyFile),
}

#[derive(Debug, Clone, interactive_clap::InteractiveClap, serde::Serialize, serde::Deserialize)]

pub struct Cmd {
    #[interactive_clap(subcommand)]
    pub subcommand: SubCommand,
}

// this str const should start from "0x"
const CHAIN_ID_PREFIX: &str = "0x56"; // V in hex

impl interactive_clap::ToCli for ChainID {
    type CliVariant = u64;
}

impl TryFrom<CliCmd> for Cmd {
    type Error = Box<dyn Error>;
    fn try_from(value: CliCmd) -> Result<Self, Self::Error> {
        let Some(subcommand) = value.subcommand else {
            return Err("No subcommand provided".into());
        };

        let subcommand = match subcommand {
            CliSubCommand::GenerateConfig(config) => SubCommand::GenerateConfig(Config {
                network_name: config.network_name.ok_or("No network name provided")?,
                token_name: config.token_name.ok_or("No token name provided")?,
                chain_id: ChainID::new(config.chain_id.ok_or("No chain id provided")?),
                hardfork: config.hardfork.ok_or("No hardfork provided")?,
                config_path: config.config_path.ok_or("No config path provided")?,
                minting_addresses: config
                    .minting_addresses
                    .ok_or("No minting addresses provided")?,
                token_symbol: config.token_symbol.ok_or("No token symbol provided")?,
                rpc_url: config.rpc_url.ok_or("No RPC URL provided")?,
            }),
            CliSubCommand::ImportGetGenesis(file_config) => {
                SubCommand::ImportGetGenesis(OnlyFile {
                    config_file: file_config.config_file.ok_or("No config file provided")?,
                })
            }
            CliSubCommand::CreateAndDeploy(file_config) => {
                SubCommand::CreateAndDeploy(DeployConfig {
                    config_file: file_config.config_file.ok_or("No config file provided")?,
                    velas_rpc: file_config.velas_rpc.ok_or("No RPC URL provided")?,
                    keypair_path: file_config.keypair_path.ok_or("No keypair path provided")?,
                    dry_run: file_config.dry_run,
                })
            }
            CliSubCommand::GetSubchainAddress(file_config) => {
                SubCommand::GetSubchainAddress(OnlyFile {
                    config_file: file_config.config_file.ok_or("No config file provided")?,
                })
            }
        };
        Ok(Cmd { subcommand })
    }
}

impl From<Config> for genesis_json::GenesisConfig {
    fn from(config: Config) -> Self {
        let mut alloc = BTreeMap::new();
        for (addr, balance, code) in zip3(
            config.minting_addresses.address.iter(),
            config.minting_addresses.balance.iter(),
            config.minting_addresses.code.iter(),
        ) {
            alloc.insert(
                *addr,
                genesis_json::Account {
                    balance: *balance,
                    nonce: 0,
                    code: code.clone(),
                    // TODO(H): implement storage in allocs
                    storage: BTreeMap::new(),
                },
            );
        }
        let config = genesis_json::GenesisConfig {
            config: genesis_json::ChainConfig {
                network_name: config.network_name,
                token_name: config.token_name,
                chain_id: config.chain_id.into(),
                start_hardfork: config.hardfork,
            },
            alloc: genesis_json::GenesisAlloc(alloc),
            auxiliary: genesis_json::OptionalConfig {
                token_symbol: config.token_symbol,
                rpc_url: config.rpc_url,
            },
        };
        config
    }
}
fn none_if_empty(val: String) -> Option<String> {
    if val.is_empty() {
        None
    } else {
        Some(val)
    }
}
impl From<genesis_json::GenesisConfig> for CliConfig {
    fn from(config: genesis_json::GenesisConfig) -> Self {
        let mut minting_addresses: MintingAddresses = Default::default();

        for (addr, account) in config.alloc.0.iter() {
            minting_addresses.address.push(*addr);
            minting_addresses.balance.push(account.balance);
        }
        CliConfig {
            network_name: none_if_empty(config.config.network_name),
            token_name: none_if_empty(config.config.token_name),
            chain_id: Some(config.config.chain_id.into()),
            hardfork: config.config.start_hardfork.into(),
            minting_addresses: Some(minting_addresses),
            token_symbol: none_if_empty(config.auxiliary.token_symbol),
            rpc_url: none_if_empty(config.auxiliary.rpc_url),
            config_path: None,
        }
    }
}

fn main() -> color_eyre::Result<()> {
    let cmd = Cmd::try_parse().ok();
    let context = (); // default: input_context = ()
    let cmd = loop {
        let cmd = <Cmd as interactive_clap::FromCli>::from_cli(cmd.clone(), context);
        match cmd {
            ResultFromCli::Ok(cmd) | ResultFromCli::Cancel(Some(cmd)) => {
                break cmd;
            }
            ResultFromCli::Cancel(None) => {
                println!("Goodbye!");
                return Ok(());
            }
            ResultFromCli::Back => {
                println!("No command choosen");
                return Ok(());
            }
            ResultFromCli::Err(optional_cli_mode, err) => {
                if let Some(cli_mode) = optional_cli_mode {
                    println!("Your console command:  {:?}", cli_mode);
                }
                return Err(err);
            }
        }
    };
    println!(
        "Your console command: {}",
        shell_words::join(&cmd.to_cli_args())
    );
    let cmd: Cmd = cmd.try_into().unwrap();

    match cmd.subcommand {
        SubCommand::GenerateConfig(config) => {
            let path = config.config_path.clone();
            println!("Saving config to file {}", path);
            let genesis_config: genesis_json::GenesisConfig = config.into();
            genesis_config.save(&path)?;
            println!("Make sure to review it before deployment.");
        }
        SubCommand::GetSubchainAddress(config) => {
            println!("Loading config from file {}", config.config_file);
            let genesis_config = genesis_json::GenesisConfig::load(&config.config_file)?;
            let program_key = solana_evm_loader_program::evm_state_subchain_account(
                genesis_config.config.chain_id.into(),
            );

            println!("EVM subchain state is stored in: {}", program_key);
        }
        SubCommand::ImportGetGenesis(file_config) => {
            println!("Loading config from file {}", file_config.config_file);
            let genesis_config = genesis_json::GenesisConfig::load(&file_config.config_file)?;

            let cli_config = CliConfig::from(genesis_config.clone());

            let config = <Config as interactive_clap::FromCli>::from_cli(
                Some(cli_config),
                InputContext {
                    skip_optional_args: false.into(),
                },
            );
            let cfg = match config {
                ResultFromCli::Ok(cfg) | ResultFromCli::Cancel(Some(cfg)) => cfg,
                ResultFromCli::Cancel(None) => {
                    println!("Goodbye!");
                    return Ok(());
                }
                ResultFromCli::Back => {
                    println!("No command choosen");
                    return Ok(());
                }
                ResultFromCli::Err(_, err) => {
                    return Err(err);
                }
            };
            let cmd = CliCmd {
                subcommand: Some(CliSubCommand::GenerateConfig(cfg)),
            };
            let cmd: Cmd = cmd.try_into().unwrap();
            let config = match cmd.subcommand {
                SubCommand::GenerateConfig(config) => config,
                _ => unreachable!(),
            };
            let path = config.config_path.clone();

            let mut genesis_config2 = genesis_json::GenesisConfig::from(config);

            let alloc = genesis_config2.alloc.0.clone();
            // Insert previous allocs
            genesis_config2.alloc = genesis_config.alloc;
            for (addr, account) in alloc.into_iter() {
                genesis_config2.alloc.0.insert(addr, account);
            }

            println!("Saving config to file {}", path);
            genesis_config2.save(&path)?;

            println!("Make sure to review it before deployment.");
        }
        SubCommand::CreateAndDeploy(file_config) => {
            println!("Loading config from file {}", file_config.config_file);
            let genesis_config = genesis_json::GenesisConfig::load(&file_config.config_file)?;
            println!("Loading keypair from file {}", file_config.keypair_path);
            let keypair = solana_sdk::signer::keypair::read_keypair_file(&file_config.keypair_path)
                .map_err(|e| {
                    color_eyre::eyre::Error::msg(format!("Cannot read keypair file: {}", e))
                })?;

            println!("Connecting to rpc {}", file_config.velas_rpc);
            let client = solana_client::rpc_client::RpcClient::new(file_config.velas_rpc);
            println!("Checking rpc connection");
            client.get_slot()?;
            println!("Deploying subchain account...");
            genesis_config.deploy(keypair, &client, false)?;
            let program_key = solana_evm_loader_program::evm_state_subchain_account(
                genesis_config.config.chain_id.into(),
            );
            println!("Deployment successful, subchain address={}", program_key);
        }
    }
    Ok(())
}
