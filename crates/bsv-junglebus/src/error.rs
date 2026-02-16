//! Error types for JungleBus operations.

/// Errors that can occur when interacting with the JungleBus API.
#[derive(Debug, thiserror::Error)]
pub enum JungleBusError {
    /// HTTP request failed.
    #[error("HTTP error: {0}")]
    HttpError(#[from] reqwest::Error),

    /// Failed to serialize or deserialize data.
    #[error("serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    /// Server returned a non-2xx response.
    #[error("server error ({status_code}): {message}")]
    ServerError {
        /// HTTP status code.
        status_code: u16,
        /// Error message from server.
        message: String,
    },

    /// Resource not found (404).
    #[error("not found")]
    NotFound,
}
