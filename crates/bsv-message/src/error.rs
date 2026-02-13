/// Error types for message operations.
#[derive(Debug, thiserror::Error)]
pub enum MessageError {
    #[error("{0}")]
    General(String),
    #[error("{0}")]
    Primitives(#[from] bsv_primitives::PrimitivesError),
    #[error("message version mismatch: Expected {expected}, received {received}")]
    VersionMismatch { expected: String, received: String },
    #[error("the encrypted message expects a recipient public key of {expected}, but the provided key is {actual}")]
    RecipientMismatch { expected: String, actual: String },
    #[error("message too short: expected at least {expected} bytes, got {actual} bytes")]
    MessageTooShort { expected: usize, actual: usize },
    #[error("this signature can only be verified with knowledge of a specific private key. The associated public key is: {0}")]
    VerifierRequired(String),
    #[error("the recipient public key is {actual} but the signature requires the recipient to have public key {expected}")]
    WrongVerifier { expected: String, actual: String },
}
