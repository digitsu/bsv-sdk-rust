/// Error types for authentication operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("auth error: {0}")]
    General(String),

    #[error("session not found")]
    SessionNotFound,

    #[error("not authenticated")]
    NotAuthenticated,

    #[error("authentication failed")]
    AuthFailed,

    #[error("invalid message")]
    InvalidMessage,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("timeout")]
    Timeout,

    #[error("transport not connected")]
    TransportNotConnected,

    #[error("invalid nonce")]
    InvalidNonce,

    #[error("missing certificate")]
    MissingCertificate,

    #[error("certificate validation failed: {0}")]
    CertificateValidation(String),

    #[error("wallet error: {0}")]
    Wallet(#[from] bsv_wallet::WalletError),

    #[error("primitives error: {0}")]
    Primitives(#[from] bsv_primitives::PrimitivesError),

    #[error("no handler registered")]
    NoHandlerRegistered,

    #[error("certificate already signed")]
    AlreadySigned,

    #[error("certificate not signed")]
    NotSigned,

    #[error("missing master keyring")]
    MissingMasterKeyring,

    #[error("field not found: {0}")]
    FieldNotFound(String),

    #[error("key not found in keyring: {0}")]
    KeyNotFoundInKeyring(String),

    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    #[error("field decryption failed: {0}")]
    FieldDecryption(String),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}
