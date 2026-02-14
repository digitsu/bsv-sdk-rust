/// Error types for script operations.
///
/// Covers parsing errors, encoding/decoding failures, address validation,
/// and script classification problems.
#[derive(Debug, thiserror::Error)]
pub enum ScriptError {
    /// Generic invalid script error.
    #[error("invalid script: {0}")]
    InvalidScript(String),

    /// An unrecognized or invalid opcode was encountered.
    #[error("invalid opcode: {0}")]
    InvalidOpcode(u8),

    /// Invalid opcode data encountered during ASM parsing.
    #[error("invalid opcode data")]
    InvalidOpcodeData,

    /// Attempted to use AppendOpcodes for a push data opcode.
    #[error("use append_push_data for push data funcs: {0}")]
    InvalidOpcodeType(String),

    /// Invalid address string.
    #[error("invalid address: {0}")]
    InvalidAddress(String),

    /// Invalid address length after Base58 decoding.
    #[error("invalid address length for '{0}'")]
    InvalidAddressLength(String),

    /// Address type not supported (not P2PKH mainnet/testnet).
    #[error("address not supported {0}")]
    UnsupportedAddress(String),

    /// Script too large.
    #[error("script too large: {0} bytes")]
    ScriptTooLarge(usize),

    /// Invalid hex string.
    #[error("invalid hex: {0}")]
    InvalidHex(String),

    /// Hex decoding error.
    #[error("hex decode error: {0}")]
    HexDecode(#[from] hex::FromHexError),

    /// Script is empty when a non-empty script was expected.
    #[error("script is empty")]
    EmptyScript,

    /// Script is not a P2PKH script.
    #[error("not a P2PKH")]
    NotP2PKH,

    /// Not enough data in script to complete a push operation.
    #[error("not enough data")]
    DataTooSmall,

    /// Push data exceeds maximum allowed size.
    #[error("data too big")]
    DataTooBig,

    /// A push data part exceeds protocol limits.
    #[error("part too big '{0}'")]
    PartTooBig(usize),

    /// Script index is out of range.
    #[error("script index out of range")]
    IndexOutOfRange,

    /// Bad character in Base58 encoding.
    #[error("bad char")]
    EncodingBadChar,

    /// Encoded value is too long for the target type.
    #[error("too long")]
    EncodingTooLong,

    /// Address version byte is not recognized (not 0x00 or 0x6f).
    #[error("not version 0 or 6f")]
    EncodingInvalidVersion,

    /// Base58Check checksum does not match.
    #[error("checksum failed")]
    EncodingChecksumFailed,

    /// Interpreter error.
    #[error("interpreter error: {0}")]
    InterpreterError(String),

    /// Error from primitives crate.
    #[error("primitives error: {0}")]
    Primitives(#[from] bsv_primitives::PrimitivesError),
}
