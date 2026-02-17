/// Error types for wallet operations.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    /// A general wallet error with a descriptive message.
    #[error("wallet error: {0}")]
    General(String),
    /// An error originating from the primitives layer.
    #[error("primitives error: {0}")]
    Primitives(#[from] bsv_primitives::PrimitivesError),
    /// The protocol identifier is invalid or malformed.
    #[error("invalid protocol: {0}")]
    InvalidProtocol(String),
    /// The key identifier is invalid or malformed.
    #[error("invalid key ID: {0}")]
    InvalidKeyId(String),
    /// The counterparty specification is invalid.
    #[error("invalid counterparty: {0}")]
    InvalidCounterparty(String),
    /// The key deriver has not been initialized.
    #[error("key deriver is undefined")]
    KeyDeriverUndefined,
    /// A required signature was not provided (nil).
    #[error("signature is nil")]
    SignatureNil,
    /// An invalid argument was supplied to a wallet method.
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}
