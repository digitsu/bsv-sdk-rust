/// Error types for transaction operations.
#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
    #[error("signing error: {0}")]
    SigningError(String),
    #[error("serialization error: {0}")]
    SerializationError(String),
    #[error("fee calculation error: {0}")]
    FeeError(String),
    #[error("script error: {0}")]
    Script(#[from] bsv_script::ScriptError),
    #[error("primitives error: {0}")]
    Primitives(#[from] bsv_primitives::PrimitivesError),
}
