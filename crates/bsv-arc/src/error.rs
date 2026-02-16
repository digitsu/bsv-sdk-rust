//! Error types for ARC operations.

/// Errors that can occur when interacting with the ARC API.
#[derive(Debug, thiserror::Error)]
pub enum ArcError {
    /// HTTP request failed.
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    /// Failed to serialize or deserialize data.
    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Transaction was rejected by ARC.
    #[error("transaction rejected ({code}): {description}")]
    Rejected {
        /// The rejection status code.
        code: i32,
        /// Human-readable rejection description.
        description: String,
    },

    /// Request timed out.
    #[error("request timed out")]
    Timeout,
}
