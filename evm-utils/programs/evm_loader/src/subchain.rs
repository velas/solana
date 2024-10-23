use {
    crate::{
        account_structure::AccountStructure,
        blockhash_queue::BlockhashQueue,
        error::EvmError,
        instructions::{Hardfork, SubchainConfig},
        scope::solana,
    },
    borsh::{BorshDeserialize, BorshSchema, BorshSerialize},
    solana_sdk::{account::ReadableAccount, borsh::get_instance_packed_len},
};

#[derive(
    BorshSerialize, BorshDeserialize, BorshSchema, Clone, Debug, PartialEq, Eq, Ord, PartialOrd,
)]
pub struct SubchainState {
    // Version is brosh enum-tag compatible - so we can later replace it with enum
    pub version: u8,
    // Configuration:
    pub hardfork: Hardfork,
    pub network_name: String,
    pub token_name: String,

    // Immutable state:
    pub owner: solana::Address,
    // Mutable state:
    pub last_hashes: BlockhashQueue,
}

impl SubchainState {
    pub fn new(config: SubchainConfig, owner: solana::Address) -> Self {
        Self {
            version: 0,
            hardfork: config.hardfork,
            network_name: config.network_name,
            token_name: config.token_name,
            owner,
            last_hashes: BlockhashQueue::new(),
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
            instructions::{Hardfork, SubchainConfig},
            solana,
        },
        evm_state::{H160, H256},
    };

    #[test]
    fn check_update_serialize() {
        let config = SubchainConfig {
            hardfork: Hardfork::Istanbul,
            network_name: "test".to_string(),
            token_name: "test".to_string(),
            alloc: vec![(H160::zero(), 12)],
        };
        let mut state = SubchainState::new(config, solana::Address::default());
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
