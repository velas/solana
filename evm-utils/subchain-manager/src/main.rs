use {
    inquire::Select,
    interactive_clap::{ResultFromCli, ToCliArgs},
    std::{error::Error, fmt::Display, str::FromStr},
    strum::{EnumDiscriminants, EnumIter, EnumMessage, IntoEnumIterator},
};

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
pub struct InputContext;

impl From<()> for InputContext {
    fn from(_value: ()) -> Self {
        InputContext
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
    token_symbol: String,

    /// Provide RPC URL for future tooling:
    #[interactive_clap(long)]
    rpc_url: String,
}

impl Config {
    fn input_minting_addresses(
        _context: &InputContext,
    ) -> color_eyre::eyre::Result<Option<MintingAddresses>> {
        let mut addresses = vec![];
        let mut balances = vec![];

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
            let balance: u64 = match inquire::CustomType::new("Balance:").prompt() {
                Ok(value) => value,
                Err(
                    inquire::error::InquireError::OperationCanceled
                    | inquire::error::InquireError::OperationInterrupted,
                ) => break,
                Err(err) => return Err(err.into()),
            };
            addresses.push(address);
            balances.push(balance);
            let naddress: Option<evm_state::H160> =
                match inquire::CustomType::new("One more minting address (esc to skip):")
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
            address = naddress.unwrap();
        }

        Ok(Some(MintingAddresses {
            address: addresses,
            balance: balances,
        }))
    }

    fn input_chain_id(_context: &InputContext) -> color_eyre::eyre::Result<Option<u64>> {
        match inquire::Text::new("Pick a Chain ID: ")
            .with_initial_value(CHAIN_ID_PREFIX)
            .with_placeholder(&format!("unique hex number, starts with {CHAIN_ID_PREFIX}"))
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
    }

    fn input_hardfork(_context: &InputContext) -> color_eyre::eyre::Result<Option<Hardfork>> {
        let variants = HardforkDiscriminants::iter().collect::<Vec<_>>();
        let selected = Select::new("Hardfork version:", variants).prompt()?;
        match selected {
            HardforkDiscriminants::Istanbul => Ok(Some(Hardfork::Istanbul)),
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, clap::Parser)]
pub struct MintingAddresses {
    address: Vec<Address>,
    balance: Vec<Balance>,
}

impl interactive_clap::ToCliArgs for MintingAddresses {
    fn to_cli_args(&self) -> std::collections::VecDeque<String> {
        let mut args = std::collections::VecDeque::new();
        for (address, balance) in self.address.iter().zip(self.balance.iter()) {
            args.push_back("--address".to_string());
            args.push_back(balance.to_string());
            args.push_back("--balance".to_string());
            args.push_back(address.to_string());
        }

        args
    }
}

impl interactive_clap::ToCli for MintingAddresses {
    type CliVariant = MintingAddresses;
}

type Balance = u64;
type Address = evm_state::Address;

#[derive(Debug, Clone, interactive_clap::InteractiveClap, serde::Serialize, serde::Deserialize)]
pub struct FileConfig {
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
}
impl FileConfig {
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

#[derive(
    Debug, EnumDiscriminants, Clone, clap::ValueEnum, serde::Serialize, serde::Deserialize,
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
    /// Deploy a new subchain using config file.
    #[strum_discriminants(strum(message = "Create and deploy new subchain from config"))]
    CreateAndDeploy(FileConfig),
}

#[derive(Debug, Clone, interactive_clap::InteractiveClap, serde::Serialize, serde::Deserialize)]

pub struct Cmd {
    #[interactive_clap(subcommand)]
    pub subcommand: SubCommand,
}

// this str const should start from "0x"
const CHAIN_ID_PREFIX: &str = "0x56"; // V in hex

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ChainID(u64);

impl From<u64> for ChainID {
    fn from(value: u64) -> Self {
        ChainID(value)
    }
}

impl From<ChainID> for u64 {
    fn from(value: ChainID) -> Self {
        value.0
    }
}

impl interactive_clap::ToCli for ChainID {
    type CliVariant = u64;
}

// impl interactive_clap::FromCli for ChainID {
//     type FromCliContext = ();
//     type FromCliError = color_eyre::eyre::Error;

//     fn from_cli(
//         optional_clap_variant: Option<<Self as interactive_clap::ToCli>::CliVariant>,
//         context: Self::FromCliContext,
//     ) -> ResultFromCli<<Self as interactive_clap::ToCli>::CliVariant, Self::FromCliError>
//     where
//         Self: Sized + interactive_clap::ToCli,
//     {
//         match optional_clap_variant {
//             Some(value) => ResultFromCli::Ok(value),
//             None => match Self::input_chain_id(&context) {
//                 Ok(Some(value)) => ResultFromCli::Ok(value.0),
//                 Ok(None) => ResultFromCli::Cancel(None),
//                 Err(err) => ResultFromCli::Err(None, err.into()),
//             },
//         }
//     }
// }

impl Display for ChainID {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:x}", self.0)
    }
}
impl FromStr for ChainID {
    type Err = std::num::ParseIntError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let value = u64::from_str_radix(s, 16)?;
        Ok(ChainID(value))
    }
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
                chain_id: ChainID(config.chain_id.ok_or("No chain id provided")?),
                hardfork: config.hardfork.ok_or("No hardfork provided")?,
                config_path: config.config_path.ok_or("No config path provided")?,
                minting_addresses: config
                    .minting_addresses
                    .ok_or("No minting addresses provided")?,
                token_symbol: config.token_symbol.ok_or("No token symbol provided")?,
                rpc_url: config.rpc_url.ok_or("No RPC URL provided")?,
            }),
            CliSubCommand::CreateAndDeploy(file_config) => {
                SubCommand::CreateAndDeploy(FileConfig {
                    config_file: file_config.config_file.ok_or("No config file provided")?,
                    velas_rpc: file_config.velas_rpc.ok_or("No RPC URL provided")?,
                    keypair_path: file_config.keypair_path.ok_or("No keypair path provided")?,
                })
            }
        };
        Ok(Cmd { subcommand })
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
            println!("Saving config to file {}", config.config_path);
            config.save()?;
        }
        SubCommand::CreateAndDeploy(file_config) => {
            println!("Loading config from file {}", file_config.config_file);
            let config = Config::load(&file_config.config_file)?;
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
            config.deploy(keypair, &client)?;
        }
    }
    Ok(())
}
