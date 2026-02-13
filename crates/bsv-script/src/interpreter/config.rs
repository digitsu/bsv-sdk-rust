//! Interpreter configuration with pre/post-genesis limits.

/// Limits applied to transactions before genesis.
pub const MAX_OPS_BEFORE_GENESIS: usize = 500;
pub const MAX_STACK_SIZE_BEFORE_GENESIS: usize = 1000;
pub const MAX_SCRIPT_SIZE_BEFORE_GENESIS: usize = 10000;
pub const MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS: usize = 520;
pub const MAX_SCRIPT_NUMBER_LENGTH_BEFORE_GENESIS: usize = 4;
pub const MAX_PUB_KEYS_PER_MULTISIG_BEFORE_GENESIS: usize = 20;

/// Script configuration limits.
pub struct Config {
    pub after_genesis: bool,
}

impl Config {
    pub fn before_genesis() -> Self {
        Config { after_genesis: false }
    }

    pub fn after_genesis() -> Self {
        Config { after_genesis: true }
    }

    pub fn max_ops(&self) -> usize {
        if self.after_genesis { i32::MAX as usize } else { MAX_OPS_BEFORE_GENESIS }
    }

    pub fn max_stack_size(&self) -> usize {
        if self.after_genesis { i32::MAX as usize } else { MAX_STACK_SIZE_BEFORE_GENESIS }
    }

    pub fn max_script_size(&self) -> usize {
        if self.after_genesis { i32::MAX as usize } else { MAX_SCRIPT_SIZE_BEFORE_GENESIS }
    }

    pub fn max_script_element_size(&self) -> usize {
        if self.after_genesis { i32::MAX as usize } else { MAX_SCRIPT_ELEMENT_SIZE_BEFORE_GENESIS }
    }

    pub fn max_script_number_length(&self) -> usize {
        if self.after_genesis { 750 * 1000 } else { MAX_SCRIPT_NUMBER_LENGTH_BEFORE_GENESIS }
    }

    pub fn max_pub_keys_per_multisig(&self) -> usize {
        if self.after_genesis { i32::MAX as usize } else { MAX_PUB_KEYS_PER_MULTISIG_BEFORE_GENESIS }
    }
}
