//! Script verification flags (bitmask).

use std::ops::{BitAnd, BitOr, BitOrAssign};

/// Script verification flags controlling interpreter behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScriptFlags(pub u32);

impl ScriptFlags {
    /// No flags set; accept all transactions.
    pub const NONE: ScriptFlags = ScriptFlags(0);
    /// Evaluate P2SH (BIP16) subscripts.
    pub const BIP16: ScriptFlags = ScriptFlags(1 << 0);
    /// Enforce strict multisig dummy element (must be OP_0).
    pub const STRICT_MULTI_SIG: ScriptFlags = ScriptFlags(1 << 1);
    /// Discourage use of upgradable NOP opcodes (NOP1-NOP10).
    pub const DISCOURAGE_UPGRADABLE_NOPS: ScriptFlags = ScriptFlags(1 << 2);
    /// Enforce OP_CHECKLOCKTIMEVERIFY (BIP65).
    pub const VERIFY_CHECKLOCKTIMEVERIFY: ScriptFlags = ScriptFlags(1 << 3);
    /// Enforce OP_CHECKSEQUENCEVERIFY (BIP112).
    pub const VERIFY_CHECKSEQUENCEVERIFY: ScriptFlags = ScriptFlags(1 << 4);
    /// Require exactly one element on the stack after execution.
    pub const VERIFY_CLEAN_STACK: ScriptFlags = ScriptFlags(1 << 5);
    /// Require strict DER encoding for signatures.
    pub const VERIFY_DER_SIGNATURES: ScriptFlags = ScriptFlags(1 << 6);
    /// Require the S value in signatures to be in the lower half of the curve order.
    pub const VERIFY_LOW_S: ScriptFlags = ScriptFlags(1 << 7);
    /// Require minimal encoding for data pushes.
    pub const VERIFY_MINIMAL_DATA: ScriptFlags = ScriptFlags(1 << 8);
    /// Require failed CHECK(MULTI)SIG operations to have empty signatures.
    pub const VERIFY_NULL_FAIL: ScriptFlags = ScriptFlags(1 << 9);
    /// Require the unlocking script to contain only push opcodes.
    pub const VERIFY_SIG_PUSH_ONLY: ScriptFlags = ScriptFlags(1 << 10);
    /// Enable SIGHASH_FORKID replay protection (BSV-specific).
    pub const ENABLE_SIGHASH_FORKID: ScriptFlags = ScriptFlags(1 << 11);
    /// Require strict signature and public key encoding.
    pub const VERIFY_STRICT_ENCODING: ScriptFlags = ScriptFlags(1 << 12);
    /// Use BIP143-style sighash algorithm for signature verification.
    pub const VERIFY_BIP143_SIGHASH: ScriptFlags = ScriptFlags(1 << 13);
    /// Indicates the UTXO being spent was created after the genesis upgrade.
    pub const UTXO_AFTER_GENESIS: ScriptFlags = ScriptFlags(1 << 14);
    /// Require OP_IF/OP_NOTIF arguments to be exactly empty or 0x01.
    pub const VERIFY_MINIMAL_IF: ScriptFlags = ScriptFlags(1 << 15);

    /// Return true if the given flag is set in this flags value.
    pub fn has_flag(self, flag: ScriptFlags) -> bool {
        self.0 & flag.0 == flag.0
    }

    /// Return true if any of the given flags are set in this flags value.
    pub fn has_any(self, flags: &[ScriptFlags]) -> bool {
        flags.iter().any(|f| self.has_flag(*f))
    }

    /// Set the given flag bits in this flags value.
    pub fn add_flag(&mut self, flag: ScriptFlags) {
        self.0 |= flag.0;
    }
}

impl BitOr for ScriptFlags {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        ScriptFlags(self.0 | rhs.0)
    }
}

impl BitOrAssign for ScriptFlags {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl BitAnd for ScriptFlags {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        ScriptFlags(self.0 & rhs.0)
    }
}
