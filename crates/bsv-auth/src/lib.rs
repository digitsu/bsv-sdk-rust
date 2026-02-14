

//! BSV Blockchain SDK - Authentication, certificates, and peer communication.
//!
//! Provides mutual authentication, session management, certificate exchange,
//! and transport layers (HTTP, WebSocket) following BRC-31 (Authrite).

pub mod brc104;
pub mod certificates;
pub mod error;
pub mod peer;
pub mod session_manager;
pub mod transport;
pub mod types;
pub mod utils;

pub use error::AuthError;
pub use peer::Peer;
pub use session_manager::{DefaultSessionManager, SessionManager};
pub use types::*;
