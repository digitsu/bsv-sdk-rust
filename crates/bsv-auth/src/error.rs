/// Error types for authentication operations.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    /// A general authentication error with a descriptive message.
    #[error("auth error: {0}")]
    General(String),

    /// The requested session was not found.
    #[error("session not found")]
    SessionNotFound,

    /// The peer has not been authenticated yet.
    #[error("not authenticated")]
    NotAuthenticated,

    /// Authentication handshake failed.
    #[error("authentication failed")]
    AuthFailed,

    /// The received message is malformed or invalid.
    #[error("invalid message")]
    InvalidMessage,

    /// The signature on a message or certificate failed verification.
    #[error("invalid signature")]
    InvalidSignature,

    /// The operation timed out waiting for a response.
    #[error("timeout")]
    Timeout,

    /// The transport layer is not connected.
    #[error("transport not connected")]
    TransportNotConnected,

    /// The nonce is invalid or failed verification.
    #[error("invalid nonce")]
    InvalidNonce,

    /// A required certificate was not provided.
    #[error("missing certificate")]
    MissingCertificate,

    /// Certificate validation failed with a descriptive reason.
    #[error("certificate validation failed: {0}")]
    CertificateValidation(String),

    /// An error from the wallet layer.
    #[error("wallet error: {0}")]
    Wallet(#[from] bsv_wallet::WalletError),

    /// An error from the primitives layer.
    #[error("primitives error: {0}")]
    Primitives(#[from] bsv_primitives::PrimitivesError),

    /// No handler has been registered for the incoming message type.
    #[error("no handler registered")]
    NoHandlerRegistered,

    /// The certificate has already been signed.
    #[error("certificate already signed")]
    AlreadySigned,

    /// The certificate has not been signed yet.
    #[error("certificate not signed")]
    NotSigned,

    /// The master keyring is missing or empty.
    #[error("missing master keyring")]
    MissingMasterKeyring,

    /// The specified field was not found in the certificate.
    #[error("field not found: {0}")]
    FieldNotFound(String),

    /// The specified key was not found in the keyring.
    #[error("key not found in keyring: {0}")]
    KeyNotFoundInKeyring(String),

    /// Decryption of a value failed.
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),

    /// Encryption of a value failed.
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),

    /// Decryption of a certificate field failed.
    #[error("field decryption failed: {0}")]
    FieldDecryption(String),

    /// Base64 decoding error.
    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    /// JSON serialization or deserialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// An internal lock was poisoned.
    #[error("internal lock error: {0}")]
    LockError(String),
}
