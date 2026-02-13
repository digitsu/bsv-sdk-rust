/// Unified error type for all primitives operations.
///
/// Covers errors from hashing, EC operations, encryption, encoding, and key management.
#[derive(Debug, thiserror::Error)]
pub enum PrimitivesError {
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("invalid WIF format: {0}")]
    InvalidWif(String),

    #[error("checksum mismatch")]
    ChecksumMismatch,

    #[error("point not on curve")]
    PointNotOnCurve,

    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },

    #[error("encryption error: {0}")]
    EncryptionError(String),

    #[error("decryption error: {0}")]
    DecryptionError(String),

    #[error("invalid hex: {0}")]
    InvalidHex(String),

    #[error("invalid hash: {0}")]
    InvalidHash(String),

    #[error("invalid base58: {0}")]
    InvalidBase58(String),

    #[error("insufficient shares for recovery: need {threshold}, got {got}")]
    InsufficientShares { threshold: usize, got: usize },

    #[error("invalid threshold: {0}")]
    InvalidThreshold(String),

    #[error("duplicate share detected")]
    DuplicateShare,

    #[error("varint too large")]
    VarIntTooLarge,

    #[error("unexpected end of data")]
    UnexpectedEof,

    #[error("{0}")]
    Other(String),
}

impl From<hex::FromHexError> for PrimitivesError {
    fn from(e: hex::FromHexError) -> Self {
        PrimitivesError::InvalidHex(e.to_string())
    }
}
