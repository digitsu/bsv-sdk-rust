//! Transport layer for auth message exchange.

use crate::error::AuthError;
use crate::types::AuthMessage;

/// Callback type for incoming transport messages.
pub type OnDataCallback = Box<dyn Fn(&AuthMessage) -> Result<(), AuthError> + Send + Sync>;

/// Transport interface for sending and receiving AuthMessages.
pub trait Transport: Send + Sync {
    /// Send an AuthMessage through the transport.
    fn send(&self, message: &AuthMessage) -> Result<(), AuthError>;

    /// Register a callback for incoming messages.
    fn on_data(&self, callback: OnDataCallback) -> Result<(), AuthError>;
}
