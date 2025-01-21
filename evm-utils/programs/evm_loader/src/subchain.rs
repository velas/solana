use {
    crate::{
        account_structure::AccountStructure,
        blockhash_queue::BlockhashQueue,
        error::EvmError,
        instructions::{Hardfork, SubchainConfig},
        scope::solana,
    },
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
    evm_state::U256,
    solana_sdk::{account::ReadableAccount, borsh::get_instance_packed_len},
};

#[derive(
    BorshSerialize,
    BorshDeserialize,
    BorshSchema,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    serde::Serialize,
)]
pub struct SubchainState {
    // Version is borsh enum-tag compatible - so we can later replace it with enum
    pub version: u8,
    pub chain_id: u64,
    // Configuration:
    pub hardfork: Hardfork,
    pub network_name: String,
    pub token_name: String,

    // Immutable state:
    pub owner: solana::Address,
    // Mutable state:
    pub last_hashes: BlockhashQueue,
    pub gas_price: U256,
    // pub whitelisted: BTreeSet<solana::Address>, // TODO: BTreeSet != BorshSchema
}

impl SubchainState {
    pub fn new(config: SubchainConfig, owner: solana::Address, chain_id: u64) -> Self {
        Self {
            version: 0,
            chain_id: chain_id,
            hardfork: config.hardfork,
            network_name: config.network_name,
            token_name: config.token_name,
            owner,
            last_hashes: BlockhashQueue::new(),
            gas_price: config.gas_price,
            // whitelisted,
        }
    }

    pub fn update(&mut self, mut updater: impl FnMut(&mut BlockhashQueue)) {
        updater(&mut self.last_hashes);
    }

    pub fn last_hashes(&self) -> &BlockhashQueue {
        &self.last_hashes
    }
    pub fn load(accounts: AccountStructure) -> Result<Self, EvmError> {
        let account = accounts
            .users
            .first()
            .unwrap() // NOTE: safe to unwrap
            .try_account_ref()
            .map_err(|_| EvmError::BorrowingFailed)?;
        let state =
            Self::try_from_slice(&account.data()).map_err(|_| EvmError::DeserializationError)?;
        Ok(state)
    }
    pub fn len(&self) -> Result<usize, EvmError> {
        get_instance_packed_len(&self).map_err(|_| EvmError::SerializationError)
    }

    // Always first account in account structure.
    pub fn save(&self, accounts: AccountStructure) -> Result<(), EvmError> {
        let mut buffer = Vec::new();
        self.serialize(&mut buffer)
            .map_err(|_| EvmError::SerializationError)?;
        accounts
            .users
            .first()
            .unwrap() // NOTE: safe to unwrap
            .try_account_ref_mut()
            .map_err(|_| EvmError::BorrowingFailed)?
            .set_data(buffer);
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use {
        super::SubchainState,
        crate::{
            evm::lamports_to_wei,
            instructions::{AllocAccount, Hardfork, SubchainConfig},
            solana,
        },
        evm_state::{H160, H256},
        std::collections::BTreeMap,
    };

    #[test]
    fn check_update_serialize() {
        let config = SubchainConfig {
            alloc: BTreeMap::from_iter([(
                H160::zero(),
                AllocAccount::new_with_balance(lamports_to_wei(12)),
            )]),
            hardfork: Hardfork::Istanbul,
            network_name: "test".to_string(),
            token_name: "test".to_string(),
            whitelisted: Default::default(),
            gas_price: 123.into(),
        };
        let mut state = SubchainState::new(config, solana::Address::default(), 0);
        state.update(|h| h.push(H256::repeat_byte(0x11), 12));
        assert_eq!(
            state.last_hashes().get_hashes()[255],
            H256::repeat_byte(0x11)
        );

        state.update(|h| h.push(H256::repeat_byte(0x22), 33));

        assert_eq!(
            state.last_hashes().get_hashes()[255],
            H256::repeat_byte(0x22)
        );
    }
}
