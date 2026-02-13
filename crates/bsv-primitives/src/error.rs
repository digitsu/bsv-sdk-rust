/// Unified error type for all primitives operations.
///
/// Covers errors from hashing, EC operations, encryption, encoding, and key management.
#[derive(Debug, thiserror::Error)]
pub enum PrimitivesError {
    /// Invalid private key data.
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),

    /// Invalid public key data.
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Invalid signature data.
    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    /// Malformed WIF-encoded key.
    #[error("invalid WIF format: {0}")]
    InvalidWif(String),

    /// Base58Check checksum did not match.
    #[error("checksum mismatch")]
    ChecksumMismatch,

    /// EC point is not on the secp256k1 curve.
    #[error("point not on curve")]
    PointNotOnCurve,

    /// Key length does not match the expected size.
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength {
        /// Expected length in bytes.
        expected: usize,
        /// Actual length in bytes.
        got: usize,
    },

    /// AES-GCM encryption failed.
    #[error("encryption error: {0}")]
    EncryptionError(String),

    /// AES-GCM decryption or authentication failed.
    #[error("decryption error: {0}")]
    DecryptionError(String),

    /// Invalid hexadecimal string.
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    /// Invalid hash value.
    #[error("invalid hash: {0}")]
    InvalidHash(String),

    /// Invalid Base58 encoding.
    #[error("invalid base58: {0}")]
    InvalidBase58(String),

    /// Not enough Shamir shares to reconstruct the secret.
    #[error("insufficient shares for recovery: need {threshold}, got {got}")]
    InsufficientShares {
        /// Minimum shares required.
        threshold: usize,
        /// Shares actually provided.
        got: usize,
    },

    /// Shamir threshold value is invalid.
    #[error("invalid threshold: {0}")]
    InvalidThreshold(String),

    /// Duplicate Shamir share index.
    #[error("duplicate share detected")]
    DuplicateShare,

    /// Variable-length integer exceeds maximum size.
    #[error("varint too large")]
    VarIntTooLarge,

    /// Unexpected end of input data.
    #[error("unexpected end of data")]
    UnexpectedEof,

    /// Catch-all error.
    #[error("{0}")]
    Other(String),
}

impl From<hex::FromHexError> for PrimitivesError {
    fn from(e: hex::FromHexError) -> Self {
        PrimitivesError::InvalidHex(e.to_string())
    }
}
