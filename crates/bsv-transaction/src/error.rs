/// Error types for transaction operations.
#[derive(Debug, thiserror::Error)]
pub enum TransactionError {
    /// The transaction structure is invalid (e.g. missing inputs or outputs).
    #[error("invalid transaction: {0}")]
    InvalidTransaction(String),
    /// An error occurred during input signing (e.g. missing source output).
    #[error("signing error: {0}")]
    SigningError(String),
    /// An error occurred during binary/hex serialization or deserialization.
    #[error("serialization error: {0}")]
    SerializationError(String),
    /// Fee calculation failed (e.g. insufficient funds or invalid fee rate).
    #[error("fee calculation error: {0}")]
    FeeError(String),
    /// An underlying script error (forwarded from `bsv-script`).
    #[error("script error: {0}")]
    Script(#[from] bsv_script::ScriptError),
    /// An underlying primitives error (forwarded from `bsv-primitives`).
    #[error("primitives error: {0}")]
    Primitives(#[from] bsv_primitives::PrimitivesError),
}
