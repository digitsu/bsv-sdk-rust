//! Transaction broadcasting interfaces.
//!
//! Ported from the Go SDK's `broadcaster.go`.

use bsv_transaction::Transaction;

use crate::error::SpvError;

/// Result of a successful broadcast.
#[derive(Debug, Clone)]
pub struct BroadcastSuccess {
    /// The transaction ID returned by the network.
    pub txid: String,
    /// Human-readable status message from the broadcaster.
    pub message: String,
}

/// Result of a failed broadcast.
#[derive(Debug, Clone)]
pub struct BroadcastFailure {
    /// Machine-readable error code from the broadcaster.
    pub code: String,
    /// Human-readable description of the failure.
    pub description: String,
}

impl std::fmt::Display for BroadcastFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.description)
    }
}

impl std::error::Error for BroadcastFailure {}

/// Trait for broadcasting transactions to the network.
pub trait Broadcaster {
    /// Broadcast a transaction.
    ///
    /// # Returns
    /// `Ok(BroadcastSuccess)` on success, or `Err` containing the failure.
    fn broadcast(&self, tx: &Transaction) -> Result<BroadcastSuccess, SpvError>;
}
