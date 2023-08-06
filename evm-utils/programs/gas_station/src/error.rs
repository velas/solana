use num_derive::FromPrimitive;
use solana_sdk::program_error::ProgramError;
use thiserror::Error;

#[derive(Clone, Debug, Eq, Error, FromPrimitive, PartialEq)]
pub enum GasStationError {
    /// The account cannot be initialized because it is already being used.
    #[error("Account is already in use")]
    AccountInUse,
    #[error("Account isn't authorized for this instruction")]
    AccountNotAuthorized,
    #[error("Account storage isn't uninitialized")]
    AccountNotInitialized,
    #[error("Account info for big transaction storage is missing")]
    BigTxStorageMissing,
    #[error("Filters provided in instruction are the same as in storage")]
    FiltersNotChanged,
    #[error("Payer is unable to pay for transaction")]
    InsufficientPayerBalance,
    #[error("Unable to deserialize borsh encoded account data")]
    InvalidAccountBorshData,
    #[error("Unable to deserialize big transaction account data")]
    InvalidBigTransactionData,
    #[error("Invalid evm loader account")]
    InvalidEvmLoader,
    #[error("Invalid evm state account")]
    InvalidEvmState,
    #[error("Invalid filter amount")]
    InvalidFilterAmount,
    #[error("Lamport balance below rent-exempt threshold")]
    NotRentExempt,
    #[error("Payer account doesn't match key from payer storage")]
    PayerAccountMismatch,
    #[error("None of payer filters correspond to evm transaction")]
    PayerFilterMismatch,
    #[error("PDA account info doesn't match DPA derived by this program id")]
    PdaAccountMismatch,
    #[error("Overflow occurred during transaction call refund")]
    RefundOverflow,
    #[error("Functionality is not supported")]
    NotSupported,
}

impl From<GasStationError> for ProgramError {
    fn from(e: GasStationError) -> Self {
        ProgramError::Custom(e as u32)
    }
}
