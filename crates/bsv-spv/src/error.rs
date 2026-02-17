/// Error types for SPV operations.
#[derive(Debug, thiserror::Error)]
pub enum SpvError {
    /// General SPV error with a descriptive message.
    #[error("spv error: {0}")]
    General(String),
    /// Error propagated from the transaction layer.
    #[error("transaction error: {0}")]
    Transaction(#[from] bsv_transaction::TransactionError),
    /// Error propagated from the primitives layer.
    #[error("primitives error: {0}")]
    Primitives(#[from] bsv_primitives::PrimitivesError),
    /// Invalid BEEF container (malformed data, bad version, etc.).
    #[error("invalid BEEF: {0}")]
    InvalidBeef(String),
    /// Invalid Merkle path / BUMP (missing hashes, wrong structure, etc.).
    #[error("invalid merkle path: {0}")]
    InvalidMerklePath(String),
    /// Hex decoding error.
    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),
}
