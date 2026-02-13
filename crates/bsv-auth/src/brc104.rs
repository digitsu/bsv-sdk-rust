//! BRC-104 HTTP header constants for BSV authentication over HTTP transport.

pub const AUTH_HEADER_PREFIX: &str = "x-bsv-auth";
pub const HEADER_VERSION: &str = "x-bsv-auth-version";
pub const HEADER_MESSAGE_TYPE: &str = "x-bsv-auth-message-type";
pub const HEADER_IDENTITY_KEY: &str = "x-bsv-auth-identity-key";
pub const HEADER_NONCE: &str = "x-bsv-auth-nonce";
pub const HEADER_YOUR_NONCE: &str = "x-bsv-auth-your-nonce";
pub const HEADER_SIGNATURE: &str = "x-bsv-auth-signature";
pub const HEADER_REQUEST_ID: &str = "x-bsv-auth-request-id";
pub const HEADER_REQUESTED_CERTIFICATES: &str = "x-bsv-auth-requested-certificates";
pub const REQUEST_ID_LENGTH: usize = 32;
