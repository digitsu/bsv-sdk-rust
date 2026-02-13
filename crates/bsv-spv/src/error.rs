/// Error types for SPV operations.
#[derive(Debug, thiserror::Error)]
pub enum SpvError {
    #[error("spv error: {0}")]
    General(String),
    #[error("transaction error: {0}")]
    Transaction(#[from] bsv_transaction::TransactionError),
    #[error("primitives error: {0}")]
    Primitives(#[from] bsv_primitives::PrimitivesError),
    #[error("invalid BEEF: {0}")]
    InvalidBeef(String),
    #[error("invalid merkle path: {0}")]
    InvalidMerklePath(String),
    #[error("hex error: {0}")]
    Hex(#[from] hex::FromHexError),
}
