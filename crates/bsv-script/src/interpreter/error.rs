//! Interpreter error types matching the Go SDK's errs package.

use std::fmt;

/// Error codes for the script interpreter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InterpreterErrorCode {
    Internal,
    Ok,
    InvalidFlags,
    InvalidIndex,
    UnsupportedAddress,
    NotMultisigScript,
    TooManyRequiredSigs,
    TooMuchNullData,
    InvalidParams,
    EarlyReturn,
    EmptyStack,
    EvalFalse,
    ScriptUnfinished,
    InvalidProgramCounter,
    ScriptTooBig,
    ElementTooBig,
    TooManyOperations,
    StackOverflow,
    InvalidPubKeyCount,
    InvalidSignatureCount,
    NumberTooBig,
    NumberTooSmall,
    DivideByZero,
    Verify,
    EqualVerify,
    NumEqualVerify,
    CheckSigVerify,
    CheckMultiSigVerify,
    DisabledOpcode,
    ReservedOpcode,
    MalformedPush,
    InvalidStackOperation,
    UnbalancedConditional,
    InvalidInputLength,
    MinimalData,
    MinimalIf,
    InvalidSigHashType,
    SigTooShort,
    SigTooLong,
    SigInvalidSeqID,
    SigInvalidDataLen,
    SigMissingSTypeID,
    SigMissingSLen,
    SigInvalidSLen,
    SigInvalidRIntID,
    SigZeroRLen,
    SigNegativeR,
    SigTooMuchRPadding,
    SigInvalidSIntID,
    SigZeroSLen,
    SigNegativeS,
    SigTooMuchSPadding,
    SigHighS,
    NotPushOnly,
    SigNullDummy,
    PubKeyType,
    CleanStack,
    NullFail,
    DiscourageUpgradableNOPs,
    NegativeLockTime,
    UnsatisfiedLockTime,
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
    pub code: InterpreterErrorCode,
    pub description: String,
}

impl InterpreterError {
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
