use {
    crate::{
        parse_bpf_loader::parse_bpf_upgradeable_loader,
        parse_config::parse_config,
        parse_nonce::parse_nonce,
        parse_stake::parse_stake,
        parse_sysvar::parse_sysvar,
        parse_token::{parse_token, spl_token_2022_id, spl_token_id},
        parse_vote::parse_vote,
    },
    borsh::BorshDeserialize,
    inflector::Inflector,
    serde_json::Value,
    solana_sdk::{
        evm_state, instruction::InstructionError, pubkey::Pubkey, stake, system_program, sysvar,
    },
    std::{collections::HashMap, convert::TryFrom},
    thiserror::Error,
};

lazy_static! {
    static ref BPF_UPGRADEABLE_LOADER_PROGRAM_ID: Pubkey = solana_sdk::bpf_loader_upgradeable::id();
    static ref CONFIG_PROGRAM_ID: Pubkey = solana_config_program::id();
    static ref STAKE_PROGRAM_ID: Pubkey = stake::program::id();
    static ref SYSTEM_PROGRAM_ID: Pubkey = system_program::id();
    static ref SYSVAR_PROGRAM_ID: Pubkey = sysvar::id();
    static ref VOTE_PROGRAM_ID: Pubkey = solana_vote_program::id();
    static ref VELAS_ACCOUNT_PROGRAM_ID: Pubkey = velas_account_program::id();
    static ref EVM_PROGRAM_ID: Pubkey = evm_state::id();
    static ref VELAS_RELYING_PARTY_PROGRAM_ID: Pubkey = velas_relying_party_program::id();
    pub static ref PARSABLE_PROGRAM_IDS: HashMap<Pubkey, ParsableAccount> = {
        let mut m = HashMap::new();
        m.insert(
            *BPF_UPGRADEABLE_LOADER_PROGRAM_ID,
            ParsableAccount::BpfUpgradeableLoader,
        );
        m.insert(*CONFIG_PROGRAM_ID, ParsableAccount::Config);
        m.insert(*SYSTEM_PROGRAM_ID, ParsableAccount::Nonce);
        m.insert(spl_token_id(), ParsableAccount::SplToken);
        m.insert(spl_token_2022_id(), ParsableAccount::SplToken2022);
        m.insert(*STAKE_PROGRAM_ID, ParsableAccount::Stake);
        m.insert(*SYSVAR_PROGRAM_ID, ParsableAccount::Sysvar);
        m.insert(*VOTE_PROGRAM_ID, ParsableAccount::Vote);
        m.insert(*EVM_PROGRAM_ID, ParsableAccount::EvmState);
        m.insert(*VELAS_ACCOUNT_PROGRAM_ID, ParsableAccount::VelasAccount);
        m.insert(
            *VELAS_RELYING_PARTY_PROGRAM_ID,
            ParsableAccount::VelasRelyingParty,
        );
        m
    };
}

#[derive(Error, Debug)]
pub enum ParseAccountError {
    #[error("{0:?} account not parsable")]
    AccountNotParsable(ParsableAccount),

    #[error("Program not parsable")]
    ProgramNotParsable,

    #[error("Additional data required to parse: {0}")]
    AdditionalDataMissing(String),

    #[error("Instruction error")]
    InstructionError(#[from] InstructionError),

    #[error("Serde json error")]
    SerdeJsonError(#[from] serde_json::error::Error),
}

impl From<velas_account_program::ParseError> for ParseAccountError {
    fn from(err: velas_account_program::ParseError) -> Self {
        match err {
            velas_account_program::ParseError::AccountNotParsable => {
                Self::AccountNotParsable(ParsableAccount::VelasAccount)
            }
        }
    }
}

impl From<velas_relying_party_program::ParseError> for ParseAccountError {
    fn from(err: velas_relying_party_program::ParseError) -> Self {
        match err {
            velas_relying_party_program::ParseError::AccountNotParsable => {
                Self::AccountNotParsable(ParsableAccount::VelasRelyingParty)
            }
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ParsedAccount {
    pub program: String,
    pub parsed: Value,
    pub space: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ParsableAccount {
    BpfUpgradeableLoader,
    Config,
    Nonce,
    SplToken,
    SplToken2022,
    Stake,
    Sysvar,
    Vote,
    EvmState,
    VelasAccount,
    VelasRelyingParty,
}

#[derive(Default)]
pub struct AccountAdditionalData {
    pub spl_token_decimals: Option<u8>,
}

pub fn parse_account_data(
    pubkey: &Pubkey,
    program_id: &Pubkey,
    data: &[u8],
    additional_data: Option<AccountAdditionalData>,
) -> Result<ParsedAccount, ParseAccountError> {
    let program_name = PARSABLE_PROGRAM_IDS
        .get(program_id)
        .ok_or(ParseAccountError::ProgramNotParsable)?;
    let additional_data = additional_data.unwrap_or_default();
    let parsed_json = match program_name {
        ParsableAccount::BpfUpgradeableLoader => {
            serde_json::to_value(parse_bpf_upgradeable_loader(data)?)?
        }
        ParsableAccount::Config => serde_json::to_value(parse_config(data, pubkey)?)?,
        ParsableAccount::Nonce => serde_json::to_value(parse_nonce(data)?)?,
        ParsableAccount::SplToken | ParsableAccount::SplToken2022 => {
            serde_json::to_value(parse_token(data, additional_data.spl_token_decimals)?)?
        }
        ParsableAccount::Stake => serde_json::to_value(parse_stake(data)?)?,
        ParsableAccount::Sysvar => serde_json::to_value(parse_sysvar(data, pubkey)?)?,
        ParsableAccount::Vote => serde_json::to_value(parse_vote(data)?)?,
        ParsableAccount::EvmState => {
            let val = solana_evm_loader_program::subchain::SubchainState::try_from_slice(data)
                .map_err(|_e| ParseAccountError::AccountNotParsable(ParsableAccount::EvmState))?;
            let expected_addr = solana_evm_loader_program::evm_state_subchain_account(val.chain_id);
            if pubkey != &expected_addr {
                return Err(ParseAccountError::AccountNotParsable(
                    ParsableAccount::EvmState,
                ));
            };

            serde_json::to_value(val)?
        }
        ParsableAccount::VelasAccount => {
            serde_json::to_value(velas_account_program::VelasAccountType::try_from(data)?)?
        }
        ParsableAccount::VelasRelyingParty => serde_json::to_value(
            velas_relying_party_program::RelyingPartyData::try_from(data)?,
        )?,
    };
    Ok(ParsedAccount {
        program: format!("{:?}", program_name).to_kebab_case(),
        parsed: parsed_json,
        space: data.len() as u64,
    })
}

#[cfg(test)]
mod test {
    use {
        super::*,
        crate::parse_account_data,
        serde_json::json,
        solana_evm_loader_program::{
            instructions::{Hardfork, SubchainConfig},
            subchain::SubchainState,
        },
        solana_sdk::nonce::{
            state::{Data, Versions},
            State,
        },
        solana_vote_program::vote_state::{VoteState, VoteStateVersions},
    };

    #[test]
    fn test_parse_account_data() {
        let account_pubkey = solana_sdk::pubkey::new_rand();
        let other_program = solana_sdk::pubkey::new_rand();
        let data = vec![0; 4];
        assert!(parse_account_data(&account_pubkey, &other_program, &data, None).is_err());

        let vote_state = VoteState::default();
        let mut vote_account_data: Vec<u8> = vec![0; VoteState::size_of()];
        let versioned = VoteStateVersions::new_current(vote_state);
        VoteState::serialize(&versioned, &mut vote_account_data).unwrap();
        let parsed = parse_account_data(
            &account_pubkey,
            &solana_vote_program::id(),
            &vote_account_data,
            None,
        )
        .unwrap();
        assert_eq!(parsed.program, "vote".to_string());
        assert_eq!(parsed.space, VoteState::size_of() as u64);

        let nonce_data = Versions::new(
            State::Initialized(Data::default()),
            true, // separate_domains
        );
        let nonce_account_data = bincode::serialize(&nonce_data).unwrap();
        let parsed = parse_account_data(
            &account_pubkey,
            &system_program::id(),
            &nonce_account_data,
            None,
        )
        .unwrap();

        assert_eq!(parsed.program, "nonce".to_string());
        assert_eq!(parsed.space, State::size() as u64);
        let evm_state_subchain = SubchainState::new(
            SubchainConfig {
                alloc: Default::default(),
                hardfork: Hardfork::Istanbul,
                token_name: "token_name".to_string(),
                network_name: "network_name".to_string(),
                whitelisted: [Pubkey::new_from_array([15; 32])].into(),
                min_gas_price: 15.into(),
            },
            account_pubkey,
            1,
        );
        let data = ::borsh::BorshSerialize::try_to_vec(&evm_state_subchain).unwrap();
        let account = parse_account_data(
            &solana_evm_loader_program::evm_state_subchain_account(1),
            &evm_state::id(),
            &data,
            None,
        )
        .unwrap();

        assert_eq!(account.program, "evm-state".to_string());

        let parsed = account.parsed.as_object().unwrap();

        let assert_field = |name: &str, value: Value| {
            assert_eq!(
                parsed
                    .get(name)
                    .expect(&format!("field `{name}` not found")),
                &value
            );
        };

        assert_field("token_name", json!("token_name"));
        assert_field("chain_id", json!(1));
        assert_field("network_name", json!("network_name"));
        assert_field("min_gas_price", json!("0xf"));
        assert_field(
            "whitelisted",
            json!([[
                15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
                15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15
            ]]),
        );
    }
}
