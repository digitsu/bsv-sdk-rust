/// Error types for wallet operations.
#[derive(Debug, thiserror::Error)]
pub enum WalletError {
    #[error("wallet error: {0}")]
    General(String),
    #[error("primitives error: {0}")]
    Primitives(#[from] bsv_primitives::PrimitivesError),
    #[error("invalid protocol: {0}")]
    InvalidProtocol(String),
    #[error("invalid key ID: {0}")]
    InvalidKeyId(String),
    #[error("invalid counterparty: {0}")]
    InvalidCounterparty(String),
    #[error("key deriver is undefined")]
    KeyDeriverUndefined,
    #[error("signature is nil")]
    SignatureNil,
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
}
