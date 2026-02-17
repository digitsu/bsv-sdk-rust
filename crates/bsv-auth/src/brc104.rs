//! BRC-104 HTTP header constants for BSV authentication over HTTP transport.

/// Common prefix for all BSV authentication HTTP headers.
pub const AUTH_HEADER_PREFIX: &str = "x-bsv-auth";
/// HTTP header for the auth protocol version.
pub const HEADER_VERSION: &str = "x-bsv-auth-version";
/// HTTP header for the auth message type.
pub const HEADER_MESSAGE_TYPE: &str = "x-bsv-auth-message-type";
/// HTTP header for the sender's identity public key.
pub const HEADER_IDENTITY_KEY: &str = "x-bsv-auth-identity-key";
/// HTTP header for the sender's nonce.
pub const HEADER_NONCE: &str = "x-bsv-auth-nonce";
/// HTTP header echoing back the recipient's nonce.
pub const HEADER_YOUR_NONCE: &str = "x-bsv-auth-your-nonce";
/// HTTP header for the digital signature.
pub const HEADER_SIGNATURE: &str = "x-bsv-auth-signature";
/// HTTP header for the request identifier.
pub const HEADER_REQUEST_ID: &str = "x-bsv-auth-request-id";
/// HTTP header for requested certificates (JSON-encoded).
pub const HEADER_REQUESTED_CERTIFICATES: &str = "x-bsv-auth-requested-certificates";
/// Length in bytes of the request ID.
pub const REQUEST_ID_LENGTH: usize = 32;
