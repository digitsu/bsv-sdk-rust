//! Interpreter error types matching the Go SDK's errs package.

use std::fmt;

/// Error codes for the script interpreter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterpreterErrorCode {
    /// An internal interpreter error occurred.
    Internal,
    /// No error; used as a sentinel for early successful return.
    Ok,
    /// The combination of script flags is invalid.
    InvalidFlags,
    /// An index is out of range for the operation.
    InvalidIndex,
    /// The address type is not supported.
    UnsupportedAddress,
    /// The script is not a valid multisig script.
    NotMultisigScript,
    /// The number of required signatures exceeds the allowed maximum.
    TooManyRequiredSigs,
    /// The OP_RETURN data payload exceeds the allowed size.
    TooMuchNullData,
    /// Invalid parameters were supplied to the interpreter.
    InvalidParams,
    /// Script execution returned early (post-genesis OP_RETURN).
    EarlyReturn,
    /// The stack is empty when an operand was expected.
    EmptyStack,
    /// The top stack value is false at the end of script execution.
    EvalFalse,
    /// Script execution ended before all opcodes were processed.
    ScriptUnfinished,
    /// The program counter points to an invalid script position.
    InvalidProgramCounter,
    /// The script exceeds the maximum allowed size.
    ScriptTooBig,
    /// A data element exceeds the maximum allowed element size.
    ElementTooBig,
    /// The number of non-push opcodes exceeds the allowed maximum.
    TooManyOperations,
    /// The combined data and alt stack size exceeds the allowed maximum.
    StackOverflow,
    /// The public key count in a multisig is out of range.
    InvalidPubKeyCount,
    /// The signature count in a multisig is out of range.
    InvalidSignatureCount,
    /// A numeric operand exceeds the maximum allowed byte length.
    NumberTooBig,
    /// A numeric operand is below the minimum allowed value.
    NumberTooSmall,
    /// Division or modulo by zero was attempted.
    DivideByZero,
    /// OP_VERIFY failed because the top stack value is false.
    Verify,
    /// OP_EQUALVERIFY failed because the top two values are not equal.
    EqualVerify,
    /// OP_NUMEQUALVERIFY failed because the top two numeric values differ.
    NumEqualVerify,
    /// OP_CHECKSIGVERIFY failed because signature verification failed.
    CheckSigVerify,
    /// OP_CHECKMULTISIGVERIFY failed because multisig verification failed.
    CheckMultiSigVerify,
    /// A disabled opcode was encountered during execution.
    DisabledOpcode,
    /// A reserved opcode was encountered during execution.
    ReservedOpcode,
    /// A push opcode has a malformed or truncated data payload.
    MalformedPush,
    /// A stack operation references an invalid stack index.
    InvalidStackOperation,
    /// An IF/ELSE/ENDIF block is not properly balanced.
    UnbalancedConditional,
    /// An input length is invalid for the operation.
    InvalidInputLength,
    /// A data push does not use the minimal encoding required by policy.
    MinimalData,
    /// An OP_IF/OP_NOTIF argument is not minimally encoded (must be empty or 0x01).
    MinimalIf,
    /// The sighash type byte in a signature is invalid.
    InvalidSigHashType,
    /// The DER-encoded signature is shorter than the minimum valid length.
    SigTooShort,
    /// The DER-encoded signature is longer than the maximum valid length.
    SigTooLong,
    /// The DER sequence identifier byte is missing or invalid.
    SigInvalidSeqID,
    /// The DER data length field does not match the actual signature length.
    SigInvalidDataLen,
    /// The DER S-type identifier byte (0x02) is missing.
    SigMissingSTypeID,
    /// The DER S-length field is missing.
    SigMissingSLen,
    /// The DER S-length value is invalid.
    SigInvalidSLen,
    /// The DER R integer type identifier byte (0x02) is invalid.
    SigInvalidRIntID,
    /// The DER R value has zero length.
    SigZeroRLen,
    /// The DER R value is negative (leading byte has high bit set without padding).
    SigNegativeR,
    /// The DER R value has excessive zero-byte padding.
    SigTooMuchRPadding,
    /// The DER S integer type identifier byte (0x02) is invalid.
    SigInvalidSIntID,
    /// The DER S value has zero length.
    SigZeroSLen,
    /// The DER S value is negative (leading byte has high bit set without padding).
    SigNegativeS,
    /// The DER S value has excessive zero-byte padding.
    SigTooMuchSPadding,
    /// The S value in the signature is not in the low-S canonical form.
    SigHighS,
    /// The unlocking script contains non-push opcodes when push-only is required.
    NotPushOnly,
    /// The dummy element for OP_CHECKMULTISIG is not empty (null dummy rule).
    SigNullDummy,
    /// A public key does not conform to the required encoding format.
    PubKeyType,
    /// The stack contains extra items after execution when clean stack is enforced.
    CleanStack,
    /// A failed signature check did not have an empty signature (NULLFAIL rule).
    NullFail,
    /// An upgradable NOP opcode was encountered and the discourage flag is set.
    DiscourageUpgradableNOPs,
    /// The lock time value is negative.
    NegativeLockTime,
    /// The transaction lock time does not satisfy OP_CHECKLOCKTIMEVERIFY.
    UnsatisfiedLockTime,
    /// The SIGHASH_FORKID flag is missing or incorrectly set.
    IllegalForkID,
}

impl fmt::Display for InterpreterErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

/// A script interpreter error with an error code and description.
#[derive(Debug, Clone)]
pub struct InterpreterError {
    /// The error code identifying the class of error.
    pub code: InterpreterErrorCode,
    /// A human-readable description of the error.
    pub description: String,
}

impl InterpreterError {
    /// Create a new interpreter error from an error code and description string.
    pub fn new(code: InterpreterErrorCode, description: String) -> Self {
        InterpreterError { code, description }
    }
}

impl fmt::Display for InterpreterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.description)
    }
}

impl std::error::Error for InterpreterError {}

/// Check if an error has a specific error code.
pub fn is_error_code(err: &InterpreterError, code: InterpreterErrorCode) -> bool {
    err.code == code
}
