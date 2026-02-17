//! Core auth types — AuthMessage, MessageType, PeerSession, RequestedCertificateSet.

use bsv_primitives::ec::public_key::PublicKey;
use serde::{Deserialize, Serialize};

use crate::certificates::VerifiableCertificate;

/// Auth protocol version.
pub const AUTH_VERSION: &str = "0.1";

/// Protocol ID for authentication message signatures (BRC-31 Authrite).
pub const AUTH_PROTOCOL_ID: &str = "auth message signature";

/// Message types exchanged in the auth protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Initial authentication request from the initiating peer.
    #[serde(rename = "initialRequest")]
    InitialRequest,
    /// Response to an initial authentication request.
    #[serde(rename = "initialResponse")]
    InitialResponse,
    /// Request for certificates from a peer.
    #[serde(rename = "certificateRequest")]
    CertificateRequest,
    /// Response containing certificates.
    #[serde(rename = "certificateResponse")]
    CertificateResponse,
    /// A general authenticated message.
    #[serde(rename = "general")]
    General,
}

impl std::fmt::Display for MessageType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MessageType::InitialRequest => write!(f, "initialRequest"),
            MessageType::InitialResponse => write!(f, "initialResponse"),
            MessageType::CertificateRequest => write!(f, "certificateRequest"),
            MessageType::CertificateResponse => write!(f, "certificateResponse"),
            MessageType::General => write!(f, "general"),
        }
    }
}

/// A message exchanged during the auth protocol.
#[derive(Debug, Clone)]
pub struct AuthMessage {
    /// Version of the auth protocol.
    pub version: String,
    /// Type of message.
    pub message_type: MessageType,
    /// Sender's identity key.
    pub identity_key: PublicKey,
    /// Sender's nonce (base64).
    pub nonce: String,
    /// The initial nonce from the initial request (for initial responses).
    pub initial_nonce: String,
    /// The recipient's nonce from a previous message.
    pub your_nonce: String,
    /// Optional certificates.
    pub certificates: Vec<VerifiableCertificate>,
    /// Optional requested certificates.
    pub requested_certificates: RequestedCertificateSet,
    /// The actual message data.
    pub payload: Vec<u8>,
    /// Digital signature covering the entire message.
    pub signature: Vec<u8>,
}

impl AuthMessage {
    /// Create a new AuthMessage with the given type and sender identity key.
    pub fn new(message_type: MessageType, identity_key: PublicKey) -> Self {
        Self {
            version: AUTH_VERSION.to_string(),
            message_type,
            identity_key,
            nonce: String::new(),
            initial_nonce: String::new(),
            your_nonce: String::new(),
            certificates: Vec::new(),
            requested_certificates: RequestedCertificateSet::default(),
            payload: Vec::new(),
            signature: Vec::new(),
        }
    }
}

/// A set of requested certificates (type IDs to field names, plus certifier keys).
#[derive(Debug, Clone, Default)]
pub struct RequestedCertificateSet {
    /// Public keys of required certifiers.
    pub certifiers: Vec<PublicKey>,
    /// Map of certificate type (base64 of `[u8; 32]`) to required field names.
    pub certificate_types: std::collections::HashMap<[u8; 32], Vec<String>>,
}

impl RequestedCertificateSet {
    /// Returns true if both certifiers and certificate types are empty.
    pub fn is_empty(&self) -> bool {
        self.certifiers.is_empty() && self.certificate_types.is_empty()
    }

    /// Returns true if any certificate types have been specified.
    pub fn has_certificate_types(&self) -> bool {
        !self.certificate_types.is_empty()
    }

    /// Returns true if any certifier public keys have been specified.
    pub fn has_certifiers(&self) -> bool {
        !self.certifiers.is_empty()
    }
}

/// A session with a peer.
#[derive(Debug, Clone)]
pub struct PeerSession {
    /// Whether the session is authenticated.
    pub is_authenticated: bool,
    /// The session nonce (our nonce).
    pub session_nonce: String,
    /// The peer's nonce.
    pub peer_nonce: String,
    /// The peer's identity key.
    pub peer_identity_key: Option<PublicKey>,
    /// The last time the session was updated (ms since epoch).
    pub last_update: i64,
}
