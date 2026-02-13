/// Error types for message operations.
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    /// General error.
    #[error("{0}")]
    General(String),
    /// Underlying primitives error.
    #[error("{0}")]
    Primitives(#[from] bsv_primitives::PrimitivesError),
    /// Message wire-format version mismatch.
    #[error("message version mismatch: Expected {expected}, received {received}")]
    VersionMismatch {
        /// Expected version string.
        expected: String,
        /// Received version string.
        received: String,
    },
    /// Recipient public key does not match the message header.
    #[error("the encrypted message expects a recipient public key of {expected}, but the provided key is {actual}")]
    RecipientMismatch {
        /// Expected recipient key hex.
        expected: String,
        /// Actual recipient key hex.
        actual: String,
    },
    /// Message byte length is below the minimum.
    #[error("message too short: expected at least {expected} bytes, got {actual} bytes")]
    MessageTooShort {
        /// Minimum required bytes.
        expected: usize,
        /// Actual bytes received.
        actual: usize,
    },
    /// Signature verification requires a specific private key.
    #[error("this signature can only be verified with knowledge of a specific private key. The associated public key is: {0}")]
    VerifierRequired(String),
    /// The verifier's public key does not match the signature.
    #[error("the recipient public key is {actual} but the signature requires the recipient to have public key {expected}")]
    WrongVerifier {
        /// Expected verifier key hex.
        expected: String,
        /// Actual verifier key hex.
        actual: String,
    },
}
