//! Script verification flags (bitmask).

use std::ops::{BitAnd, BitOr, BitOrAssign};

/// Script verification flags controlling interpreter behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ScriptFlags(pub u32);

impl ScriptFlags {
    pub const NONE: ScriptFlags = ScriptFlags(0);
    pub const BIP16: ScriptFlags = ScriptFlags(1 << 0);
    pub const STRICT_MULTI_SIG: ScriptFlags = ScriptFlags(1 << 1);
    pub const DISCOURAGE_UPGRADABLE_NOPS: ScriptFlags = ScriptFlags(1 << 2);
    pub const VERIFY_CHECKLOCKTIMEVERIFY: ScriptFlags = ScriptFlags(1 << 3);
    pub const VERIFY_CHECKSEQUENCEVERIFY: ScriptFlags = ScriptFlags(1 << 4);
    pub const VERIFY_CLEAN_STACK: ScriptFlags = ScriptFlags(1 << 5);
    pub const VERIFY_DER_SIGNATURES: ScriptFlags = ScriptFlags(1 << 6);
    pub const VERIFY_LOW_S: ScriptFlags = ScriptFlags(1 << 7);
    pub const VERIFY_MINIMAL_DATA: ScriptFlags = ScriptFlags(1 << 8);
    pub const VERIFY_NULL_FAIL: ScriptFlags = ScriptFlags(1 << 9);
    pub const VERIFY_SIG_PUSH_ONLY: ScriptFlags = ScriptFlags(1 << 10);
    pub const ENABLE_SIGHASH_FORKID: ScriptFlags = ScriptFlags(1 << 11);
    pub const VERIFY_STRICT_ENCODING: ScriptFlags = ScriptFlags(1 << 12);
    pub const VERIFY_BIP143_SIGHASH: ScriptFlags = ScriptFlags(1 << 13);
    pub const UTXO_AFTER_GENESIS: ScriptFlags = ScriptFlags(1 << 14);
    pub const VERIFY_MINIMAL_IF: ScriptFlags = ScriptFlags(1 << 15);

    pub fn has_flag(self, flag: ScriptFlags) -> bool {
        self.0 & flag.0 == flag.0
    }

    pub fn has_any(self, flags: &[ScriptFlags]) -> bool {
        flags.iter().any(|f| self.has_flag(*f))
    }

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
