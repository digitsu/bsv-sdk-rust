#![deny(missing_docs)]

//! BSV Blockchain SDK - Authentication, certificates, and peer communication.
//!
//! Provides mutual authentication, session management, certificate exchange,
//! and transport layers (HTTP, WebSocket) following BRC-31 (Authrite).

/// BRC-104 HTTP header constants for BSV authentication.
pub mod brc104;
/// BRC-31 identity certificates: Certificate, MasterCertificate, VerifiableCertificate.
pub mod certificates;
/// Error types for authentication operations.
pub mod error;
/// Peer-to-peer mutual authentication and messaging.
pub mod peer;
/// Session management for tracking authenticated peer sessions.
pub mod session_manager;
/// Transport layer abstraction for sending and receiving auth messages.
pub mod transport;
/// Core auth types: AuthMessage, MessageType, PeerSession, RequestedCertificateSet.
pub mod types;
/// Utility functions: nonce creation/verification, random base64, certificate helpers.
pub mod utils;

pub use error::AuthError;
pub use peer::Peer;
pub use session_manager::{DefaultSessionManager, SessionManager};
pub use types::*;
