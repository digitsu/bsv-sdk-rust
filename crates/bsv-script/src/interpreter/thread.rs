//! Script execution thread — the core interpreter engine.

use num_bigint::BigInt;

use crate::opcodes::*;
use crate::Script;

use super::config::Config;
use super::error::{InterpreterError, InterpreterErrorCode};
use super::flags::ScriptFlags;
use super::parsed_opcode::*;
use super::scriptnum::*;
use super::stack::*;
use super::TxContext;

/// Conditional execution constants.
const OP_COND_FALSE: i32 = 0;
const OP_COND_TRUE: i32 = 1;
const OP_COND_SKIP: i32 = 2;

/// Lock time threshold (block vs timestamp).
const LOCK_TIME_THRESHOLD: i64 = 500000000;

/// Max sequence number.
const MAX_TX_IN_SEQUENCE_NUM: u32 = 0xffffffff;
/// Sequence lock time disabled bit.
const SEQUENCE_LOCK_TIME_DISABLED: u32 = 1 << 31;
/// Sequence lock time is seconds flag.
const SEQUENCE_LOCK_TIME_IS_SECONDS: i64 = 1 << 22;
/// Sequence lock time mask.
const SEQUENCE_LOCK_TIME_MASK: i64 = 0x0000ffff;

/// The execution thread for the script interpreter.
pub struct Thread<'a> {
    pub dstack: Stack,
    pub astack: Stack,
    pub else_stack: BoolStack,
    pub cfg: Config,
    pub scripts: Vec<ParsedScript>,
    pub cond_stack: Vec<i32>,
    pub saved_first_stack: Vec<Vec<u8>>,
    pub script_idx: usize,
    pub script_off: usize,
    pub last_code_sep: usize,
    pub num_ops: usize,
    pub flags: ScriptFlags,
    pub bip16: bool,
    pub after_genesis: bool,
    pub early_return_after_genesis: bool,
    pub tx_context: Option<&'a dyn TxContext>,
    pub input_idx: usize,
}

impl<'a> Thread<'a> {
    pub fn new(
        unlocking_script: &Script,
        locking_script: &Script,
        flags: ScriptFlags,
        tx_context: Option<&'a dyn TxContext>,
        input_idx: usize,
    ) -> Result<Self, InterpreterError> {
        let after_genesis = flags.has_flag(ScriptFlags::UTXO_AFTER_GENESIS);
        let cfg = if after_genesis {
            Config::after_genesis()
        } else {
            Config::before_genesis()
        };

        let mut actual_flags = flags;

        // ForkID implies strict encoding
        if actual_flags.has_flag(ScriptFlags::ENABLE_SIGHASH_FORKID) {
            actual_flags.add_flag(ScriptFlags::VERIFY_STRICT_ENCODING);
        }

        // Clean stack requires BIP16
        if actual_flags.has_flag(ScriptFlags::VERIFY_CLEAN_STACK)
            && !actual_flags.has_flag(ScriptFlags::BIP16)
        {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidFlags,
                "invalid scriptflag combination".to_string(),
            ));
        }

        let verify_minimal_data = actual_flags.has_flag(ScriptFlags::VERIFY_MINIMAL_DATA);

        // Validate script sizes
        if unlocking_script.to_bytes().len() > cfg.max_script_size() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::ScriptTooBig,
                format!(
                    "unlocking script size {} is larger than the max allowed size {}",
                    unlocking_script.to_bytes().len(),
                    cfg.max_script_size()
                ),
            ));
        }
        if locking_script.to_bytes().len() > cfg.max_script_size() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::ScriptTooBig,
                format!(
                    "locking script size {} is larger than the max allowed size {}",
                    locking_script.to_bytes().len(),
                    cfg.max_script_size()
                ),
            ));
        }

        // Empty scripts = eval false
        if unlocking_script.to_bytes().is_empty() && locking_script.to_bytes().is_empty() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::EvalFalse,
                "false stack entry at end of script execution".to_string(),
            ));
        }

        let error_on_checksig = tx_context.is_none();

        let uscript = parse_script(unlocking_script, error_on_checksig)?;
        let lscript = parse_script(locking_script, error_on_checksig)?;

        // Verify sig push only
        if actual_flags.has_flag(ScriptFlags::VERIFY_SIG_PUSH_ONLY) && !is_push_only(&uscript) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NotPushOnly,
                "signature script is not push only".to_string(),
            ));
        }

        let bip16 = actual_flags.has_flag(ScriptFlags::BIP16) && locking_script.is_p2sh();
        if bip16 && !is_push_only(&uscript) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NotPushOnly,
                "pay to script hash is not push only".to_string(),
            ));
        }

        let scripts = vec![uscript, lscript];
        let mut script_idx = 0;

        // Skip empty unlocking script
        if unlocking_script.to_bytes().is_empty() {
            script_idx = 1;
        }

        let max_num_len = cfg.max_script_number_length();

        let thread = Thread {
            dstack: Stack::new(max_num_len, after_genesis, verify_minimal_data),
            astack: Stack::new(max_num_len, after_genesis, verify_minimal_data),
            else_stack: BoolStack::new(),
            cfg,
            scripts,
            cond_stack: Vec::new(),
            saved_first_stack: Vec::new(),
            script_idx,
            script_off: 0,
            last_code_sep: 0,
            num_ops: 0,
            flags: actual_flags,
            bip16,
            after_genesis,
            early_return_after_genesis: false,
            tx_context,
            input_idx,
        };

        Ok(thread)
    }

    pub fn has_flag(&self, flag: ScriptFlags) -> bool {
        self.flags.has_flag(flag)
    }

    pub fn has_any(&self, flags: &[ScriptFlags]) -> bool {
        self.flags.has_any(flags)
    }

    pub fn is_branch_executing(&self) -> bool {
        self.cond_stack.is_empty() || *self.cond_stack.last().unwrap() == OP_COND_TRUE
    }

    pub fn should_exec(&self, pop: &ParsedOpcode) -> bool {
        if !self.after_genesis {
            return true;
        }
        let cf = self.cond_stack.iter().all(|&v| v != OP_COND_FALSE);
        cf && (!self.early_return_after_genesis || pop.opcode == OP_RETURN)
    }

    /// Execute all scripts.
    pub fn execute(&mut self) -> Result<(), InterpreterError> {
        loop {
            let done = self.step()?;
            if done {
                break;
            }
        }
        self.check_error_condition(true)
    }

    /// Execute one step. Returns true if execution is complete.
    pub fn step(&mut self) -> Result<bool, InterpreterError> {
        // Valid PC check
        if self.script_idx >= self.scripts.len() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidProgramCounter,
                format!(
                    "past input scripts {}:{} {}:xxxx",
                    self.script_idx,
                    self.script_off,
                    self.scripts.len()
                ),
            ));
        }
        if self.script_off >= self.scripts[self.script_idx].len() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidProgramCounter,
                format!(
                    "past input scripts {}:{} {}:{:04}",
                    self.script_idx,
                    self.script_off,
                    self.script_idx,
                    self.scripts[self.script_idx].len()
                ),
            ));
        }

        let opcode = self.scripts[self.script_idx][self.script_off].clone();

        if let Err(e) = self.execute_opcode(&opcode) {
            if e.code == InterpreterErrorCode::Ok {
                // Early success (OP_RETURN after genesis)
                self.shift_script();
                return Ok(self.script_idx >= self.scripts.len());
            }
            return Err(e);
        }

        self.script_off += 1;

        // Stack size check
        let combined = self.dstack.depth() + self.astack.depth();
        if combined > self.cfg.max_stack_size() as i32 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::StackOverflow,
                format!(
                    "combined stack size {} > max allowed {}",
                    combined,
                    self.cfg.max_stack_size()
                ),
            ));
        }

        if self.script_off < self.scripts[self.script_idx].len() {
            return Ok(false);
        }

        // End of script - check conditionals
        if !self.cond_stack.is_empty() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::UnbalancedConditional,
                "end of script reached in conditional execution".to_string(),
            ));
        }

        // Alt stack doesn't persist between scripts
        self.astack.clear();

        // Move to next script
        self.shift_script();

        // BIP16 handling
        if self.bip16 && !self.after_genesis && self.script_idx <= 2 {
            match self.script_idx {
                1 => {
                    self.saved_first_stack = self.dstack.get_stack();
                }
                2 => {
                    self.check_error_condition(false)?;
                    let scr_bytes = self.saved_first_stack.last().cloned().unwrap_or_default();
                    let scr = Script::from_bytes(&scr_bytes);
                    let pops = parse_script(&scr, false)?;
                    self.scripts.push(pops);
                    let len = self.saved_first_stack.len();
                    let new_stack = self.saved_first_stack[..len.saturating_sub(1)].to_vec();
                    self.dstack.set_stack(new_stack);
                }
                _ => {}
            }
        }

        // Skip zero-length scripts
        if self.script_idx < self.scripts.len()
            && self.script_off >= self.scripts[self.script_idx].len()
        {
            self.script_idx += 1;
        }

        self.last_code_sep = 0;
        if self.script_idx >= self.scripts.len() {
            return Ok(true);
        }

        Ok(false)
    }

    fn shift_script(&mut self) {
        self.num_ops = 0;
        self.script_off = 0;
        self.script_idx += 1;
        self.early_return_after_genesis = false;
    }

    fn check_error_condition(&mut self, final_script: bool) -> Result<(), InterpreterError> {
        if self.dstack.depth() < 1 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::EmptyStack,
                "stack empty at end of script execution".to_string(),
            ));
        }

        if final_script
            && self.has_flag(ScriptFlags::VERIFY_CLEAN_STACK)
            && self.dstack.depth() != 1
        {
            return Err(InterpreterError::new(
                InterpreterErrorCode::CleanStack,
                format!(
                    "stack contains {} unexpected items",
                    self.dstack.depth() - 1
                ),
            ));
        }

        let v = self.dstack.pop_bool()?;
        if !v {
            return Err(InterpreterError::new(
                InterpreterErrorCode::EvalFalse,
                "false stack entry at end of script execution".to_string(),
            ));
        }

        Ok(())
    }

    fn execute_opcode(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        // Element size check
        if pop.data.len() > self.cfg.max_script_element_size() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::ElementTooBig,
                format!(
                    "element size {} exceeds max allowed size {}",
                    pop.data.len(),
                    self.cfg.max_script_element_size()
                ),
            ));
        }

        let exec = self.should_exec(pop);

        // Disabled opcodes fail on program counter
        if pop.is_disabled() && (!self.after_genesis || exec) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::DisabledOpcode,
                format!("attempt to execute disabled opcode {}", pop.name()),
            ));
        }

        // Always-illegal opcodes
        if pop.always_illegal() && !self.after_genesis {
            return Err(InterpreterError::new(
                InterpreterErrorCode::ReservedOpcode,
                format!("attempt to execute reserved opcode {}", pop.name()),
            ));
        }

        // Count non-push operations
        if pop.opcode > OP_16 {
            self.num_ops += 1;
            if self.num_ops > self.cfg.max_ops() {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::TooManyOperations,
                    format!("exceeded max operation limit of {}", self.cfg.max_ops()),
                ));
            }
        }

        // Not executing and not conditional => skip
        if !self.is_branch_executing() && !pop.is_conditional() {
            return Ok(());
        }

        // Minimal data push check
        if self.dstack.verify_minimal_data
            && self.is_branch_executing()
            && pop.opcode <= OP_PUSHDATA4
            && exec
        {
            pop.enforce_minimum_data_push()?;
        }

        // If we already hit OP_RETURN, skip non-conditionals
        if !exec && !pop.is_conditional() {
            return Ok(());
        }

        // Dispatch
        self.dispatch_opcode(pop)
    }

    fn dispatch_opcode(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        match pop.opcode {
            OP_FALSE => {
                self.dstack.push_byte_array(vec![]);
                Ok(())
            }
            op if (OP_DATA_1..=OP_DATA_75).contains(&op) => {
                self.dstack.push_byte_array(pop.data.clone());
                Ok(())
            }
            OP_PUSHDATA1 | OP_PUSHDATA2 | OP_PUSHDATA4 => {
                self.dstack.push_byte_array(pop.data.clone());
                Ok(())
            }
            OP_1NEGATE => {
                self.dstack.push_int(&ScriptNumber::new(-1, self.after_genesis));
                Ok(())
            }
            OP_RESERVED => self.op_reserved(pop),
            op if (OP_1..=OP_16).contains(&op) => {
                self.dstack.push_byte_array(vec![op - (OP_1 - 1)]);
                Ok(())
            }
            OP_NOP => Ok(()),
            OP_VER => self.op_reserved(pop),
            OP_IF => self.op_if(pop),
            OP_NOTIF => self.op_notif(pop),
            OP_VERIF | OP_VERNOTIF => self.op_ver_conditional(pop),
            OP_ELSE => self.op_else(pop),
            OP_ENDIF => self.op_endif(pop),
            OP_VERIFY => self.op_verify(pop),
            OP_RETURN => self.op_return(),

            // Locktime
            OP_CHECKLOCKTIMEVERIFY => self.op_check_locktime_verify(),
            OP_CHECKSEQUENCEVERIFY => self.op_check_sequence_verify(),

            // Stack ops
            OP_TOALTSTACK => self.op_to_alt_stack(),
            OP_FROMALTSTACK => self.op_from_alt_stack(),
            OP_2DROP => self.dstack.drop_n(2),
            OP_2DUP => self.dstack.dup_n(2),
            OP_3DUP => self.dstack.dup_n(3),
            OP_2OVER => self.dstack.over_n(2),
            OP_2ROT => self.dstack.rot_n(2),
            OP_2SWAP => self.dstack.swap_n(2),
            OP_IFDUP => self.op_ifdup(),
            OP_DEPTH => {
                let d = self.dstack.depth();
                self.dstack.push_int(&ScriptNumber::new(d as i64, self.after_genesis));
                Ok(())
            }
            OP_DROP => self.dstack.drop_n(1),
            OP_DUP => self.dstack.dup_n(1),
            OP_NIP => self.dstack.nip_n_discard(1),
            OP_OVER => self.dstack.over_n(1),
            OP_PICK => self.op_pick(),
            OP_ROLL => self.op_roll(),
            OP_ROT => self.dstack.rot_n(1),
            OP_SWAP => self.dstack.swap_n(1),
            OP_TUCK => self.dstack.tuck(),

            // Splice
            OP_CAT => self.op_cat(),
            OP_SPLIT => self.op_split(),
            OP_NUM2BIN => self.op_num2bin(),
            OP_BIN2NUM => self.op_bin2num(),
            OP_SIZE => self.op_size(),

            // Bitwise
            OP_INVERT => self.op_invert(),
            OP_AND => self.op_bitwise(|a, b| a & b),
            OP_OR => self.op_bitwise(|a, b| a | b),
            OP_XOR => self.op_bitwise(|a, b| a ^ b),
            OP_EQUAL => self.op_equal(),
            OP_EQUALVERIFY => self.op_equalverify(pop),
            OP_RESERVED1 | OP_RESERVED2 => self.op_reserved(pop),

            // Arithmetic
            OP_1ADD => self.op_unary_int(|m| { m.incr(); }),
            OP_1SUB => self.op_unary_int(|m| { m.decr(); }),
            OP_2MUL | OP_2DIV => Err(InterpreterError::new(
                InterpreterErrorCode::DisabledOpcode,
                format!("attempt to execute disabled opcode {}", pop.name()),
            )),
            OP_NEGATE => self.op_unary_int(|m| { m.neg(); }),
            OP_ABS => self.op_unary_int(|m| { m.abs(); }),
            OP_NOT => self.op_not(),
            OP_0NOTEQUAL => self.op_0notequal(),
            OP_ADD => self.op_add(),
            OP_SUB => self.op_sub(),
            OP_MUL => self.op_mul(),
            OP_DIV => self.op_div(),
            OP_MOD => self.op_mod(),
            OP_LSHIFT => self.op_lshift(),
            OP_RSHIFT => self.op_rshift(),
            OP_BOOLAND => self.op_bool_binop(|a, b| !a.is_zero() && !b.is_zero()),
            OP_BOOLOR => self.op_bool_binop(|a, b| !a.is_zero() || !b.is_zero()),
            OP_NUMEQUAL => self.op_bool_binop(|a, b| a.equal(b)),
            OP_NUMEQUALVERIFY => self.op_numequalverify(pop),
            OP_NUMNOTEQUAL => self.op_bool_binop(|a, b| !a.equal(b)),
            OP_LESSTHAN => self.op_bool_binop(|a, b| a.less_than(b)),
            OP_GREATERTHAN => self.op_bool_binop(|a, b| a.greater_than(b)),
            OP_LESSTHANOREQUAL => self.op_bool_binop(|a, b| a.less_than_or_equal(b)),
            OP_GREATERTHANOREQUAL => self.op_bool_binop(|a, b| a.greater_than_or_equal(b)),
            OP_MIN => self.op_min(),
            OP_MAX => self.op_max(),
            OP_WITHIN => self.op_within(),

            // Crypto
            OP_RIPEMD160 => self.op_hash(HashType::Ripemd160),
            OP_SHA1 => self.op_hash(HashType::Sha1),
            OP_SHA256 => self.op_hash(HashType::Sha256),
            OP_HASH160 => self.op_hash(HashType::Hash160),
            OP_HASH256 => self.op_hash(HashType::Hash256),
            OP_CODESEPARATOR => {
                self.last_code_sep = self.script_off;
                Ok(())
            }
            OP_CHECKSIG => self.op_checksig(),
            OP_CHECKSIGVERIFY => self.op_checksigverify(pop),
            OP_CHECKMULTISIG => self.op_checkmultisig(),
            OP_CHECKMULTISIGVERIFY => self.op_checkmultisigverify(pop),

            // NOP opcodes
            OP_NOP1 | OP_NOP4 | OP_NOP5 | OP_NOP6 | OP_NOP7 | OP_NOP8 | OP_NOP9
            | OP_NOP10 => {
                if self.has_flag(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                    return Err(InterpreterError::new(
                        InterpreterErrorCode::DiscourageUpgradableNOPs,
                        format!(
                            "OP_NOP{} reserved for soft-fork upgrades",
                            pop.opcode - (OP_NOP1 - 1)
                        ),
                    ));
                }
                Ok(())
            }

            // All unknown/invalid opcodes
            _ => Err(InterpreterError::new(
                InterpreterErrorCode::ReservedOpcode,
                format!("attempt to execute invalid opcode {}", pop.name()),
            )),
        }
    }

    // -----------------------------------------------------------------------
    // Flow control operations
    // -----------------------------------------------------------------------

    fn op_reserved(&self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        Err(InterpreterError::new(
            InterpreterErrorCode::ReservedOpcode,
            format!("attempt to execute reserved opcode {}", pop.name()),
        ))
    }

    fn op_ver_conditional(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        if self.after_genesis && !self.should_exec(pop) {
            return Ok(());
        }
        self.op_reserved(pop)
    }

    fn pop_if_bool(&mut self) -> Result<bool, InterpreterError> {
        if self.has_flag(ScriptFlags::VERIFY_MINIMAL_IF) {
            let b = self.dstack.pop_byte_array()?;
            if b.len() > 1 {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::MinimalIf,
                    format!("conditional has data of length {}", b.len()),
                ));
            }
            if b.len() == 1 && b[0] != 1 {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::MinimalIf,
                    "conditional failed".to_string(),
                ));
            }
            return Ok(as_bool(&b));
        }
        self.dstack.pop_bool()
    }

    fn op_if(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        let mut cond_val = OP_COND_FALSE;
        if self.should_exec(pop) {
            if self.is_branch_executing() {
                let ok = self.pop_if_bool()?;
                if ok {
                    cond_val = OP_COND_TRUE;
                }
            } else {
                cond_val = OP_COND_SKIP;
            }
        }
        self.cond_stack.push(cond_val);
        self.else_stack.push_bool(false);
        Ok(())
    }

    fn op_notif(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        let mut cond_val = OP_COND_FALSE;
        if self.should_exec(pop) {
            if self.is_branch_executing() {
                let ok = self.pop_if_bool()?;
                if !ok {
                    cond_val = OP_COND_TRUE;
                }
            } else {
                cond_val = OP_COND_SKIP;
            }
        }
        self.cond_stack.push(cond_val);
        self.else_stack.push_bool(false);
        Ok(())
    }

    fn op_else(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        if self.cond_stack.is_empty() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::UnbalancedConditional,
                format!(
                    "encountered opcode {} with no matching opcode to begin conditional execution",
                    pop.name()
                ),
            ));
        }

        let ok = self.else_stack.pop_bool()?;
        if ok {
            return Err(InterpreterError::new(
                InterpreterErrorCode::UnbalancedConditional,
                format!(
                    "encountered opcode {} with no matching opcode to begin conditional execution",
                    pop.name()
                ),
            ));
        }

        let idx = self.cond_stack.len() - 1;
        match self.cond_stack[idx] {
            OP_COND_TRUE => self.cond_stack[idx] = OP_COND_FALSE,
            OP_COND_FALSE => self.cond_stack[idx] = OP_COND_TRUE,
            _ => {} // OP_COND_SKIP stays
        }

        self.else_stack.push_bool(true);
        Ok(())
    }

    fn op_endif(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        if self.cond_stack.is_empty() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::UnbalancedConditional,
                format!(
                    "encountered opcode {} with no matching opcode to begin conditional execution",
                    pop.name()
                ),
            ));
        }
        self.cond_stack.pop();
        self.else_stack.pop_bool()?;
        Ok(())
    }

    fn op_verify(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        self.abstract_verify(pop, InterpreterErrorCode::Verify)
    }

    fn abstract_verify(
        &mut self,
        pop: &ParsedOpcode,
        code: InterpreterErrorCode,
    ) -> Result<(), InterpreterError> {
        let verified = self.dstack.pop_bool()?;
        if !verified {
            return Err(InterpreterError::new(
                code,
                format!("{} failed", pop.name()),
            ));
        }
        Ok(())
    }

    fn op_return(&mut self) -> Result<(), InterpreterError> {
        if !self.after_genesis {
            return Err(InterpreterError::new(
                InterpreterErrorCode::EarlyReturn,
                "script returned early".to_string(),
            ));
        }
        self.early_return_after_genesis = true;
        if self.cond_stack.is_empty() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::Ok,
                "success".to_string(),
            ));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Locktime operations
    // -----------------------------------------------------------------------

    fn op_check_locktime_verify(&mut self) -> Result<(), InterpreterError> {
        if !self.has_flag(ScriptFlags::VERIFY_CHECKLOCKTIMEVERIFY) || self.after_genesis {
            if self.has_flag(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::DiscourageUpgradableNOPs,
                    "OP_NOP2 reserved for soft-fork upgrades".to_string(),
                ));
            }
            return Ok(());
        }

        let ctx = self.tx_context.ok_or_else(|| {
            InterpreterError::new(
                InterpreterErrorCode::InvalidParams,
                "no tx context for CHECKLOCKTIMEVERIFY".to_string(),
            )
        })?;

        let so = self.dstack.peek_byte_array(0)?;
        let lock_time = ScriptNumber::from_bytes(
            &so,
            5,
            self.dstack.verify_minimal_data,
            self.after_genesis,
        )?;

        if lock_time.less_than_int(0) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NegativeLockTime,
                format!("negative lock time: {}", lock_time.to_i64()),
            ));
        }

        let tx_lock_time = ctx.lock_time() as i64;
        verify_lock_time(tx_lock_time, LOCK_TIME_THRESHOLD, lock_time.to_i64())?;

        if ctx.input_sequence(self.input_idx) == MAX_TX_IN_SEQUENCE_NUM {
            return Err(InterpreterError::new(
                InterpreterErrorCode::UnsatisfiedLockTime,
                "transaction input is finalized".to_string(),
            ));
        }

        Ok(())
    }

    fn op_check_sequence_verify(&mut self) -> Result<(), InterpreterError> {
        if !self.has_flag(ScriptFlags::VERIFY_CHECKSEQUENCEVERIFY) || self.after_genesis {
            if self.has_flag(ScriptFlags::DISCOURAGE_UPGRADABLE_NOPS) {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::DiscourageUpgradableNOPs,
                    "OP_NOP3 reserved for soft-fork upgrades".to_string(),
                ));
            }
            return Ok(());
        }

        let ctx = self.tx_context.ok_or_else(|| {
            InterpreterError::new(
                InterpreterErrorCode::InvalidParams,
                "no tx context for CHECKSEQUENCEVERIFY".to_string(),
            )
        })?;

        let so = self.dstack.peek_byte_array(0)?;
        let stack_seq = ScriptNumber::from_bytes(
            &so,
            5,
            self.dstack.verify_minimal_data,
            self.after_genesis,
        )?;

        if stack_seq.less_than_int(0) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NegativeLockTime,
                format!("negative sequence: {}", stack_seq.to_i64()),
            ));
        }

        let sequence = stack_seq.to_i64();

        if sequence & (SEQUENCE_LOCK_TIME_DISABLED as i64) != 0 {
            return Ok(());
        }

        if ctx.tx_version() < 2 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::UnsatisfiedLockTime,
                format!("invalid transaction version: {}", ctx.tx_version()),
            ));
        }

        let tx_sequence = ctx.input_sequence(self.input_idx) as i64;
        if tx_sequence & (SEQUENCE_LOCK_TIME_DISABLED as i64) != 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::UnsatisfiedLockTime,
                format!(
                    "transaction sequence has sequence locktime disabled bit set: 0x{:x}",
                    tx_sequence
                ),
            ));
        }

        let lock_time_mask = SEQUENCE_LOCK_TIME_IS_SECONDS | SEQUENCE_LOCK_TIME_MASK;
        verify_lock_time(
            tx_sequence & lock_time_mask,
            SEQUENCE_LOCK_TIME_IS_SECONDS,
            sequence & lock_time_mask,
        )
    }

    // -----------------------------------------------------------------------
    // Stack operations
    // -----------------------------------------------------------------------

    fn op_to_alt_stack(&mut self) -> Result<(), InterpreterError> {
        let data = self.dstack.pop_byte_array()?;
        self.astack.push_byte_array(data);
        Ok(())
    }

    fn op_from_alt_stack(&mut self) -> Result<(), InterpreterError> {
        let data = self.astack.pop_byte_array()?;
        self.dstack.push_byte_array(data);
        Ok(())
    }

    fn op_ifdup(&mut self) -> Result<(), InterpreterError> {
        let so = self.dstack.peek_byte_array(0)?;
        if as_bool(&so) {
            self.dstack.push_byte_array(so);
        }
        Ok(())
    }

    fn op_pick(&mut self) -> Result<(), InterpreterError> {
        let val = self.dstack.pop_int()?;
        self.dstack.pick_n(val.to_i32())
    }

    fn op_roll(&mut self) -> Result<(), InterpreterError> {
        let val = self.dstack.pop_int()?;
        self.dstack.roll_n(val.to_i32())
    }

    // -----------------------------------------------------------------------
    // Splice operations
    // -----------------------------------------------------------------------

    fn op_cat(&mut self) -> Result<(), InterpreterError> {
        let b = self.dstack.pop_byte_array()?;
        let a = self.dstack.pop_byte_array()?;
        let mut c = a;
        c.extend_from_slice(&b);
        if c.len() > self.cfg.max_script_element_size() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::ElementTooBig,
                format!(
                    "concatenated size {} exceeds max allowed size {}",
                    c.len(),
                    self.cfg.max_script_element_size()
                ),
            ));
        }
        self.dstack.push_byte_array(c);
        Ok(())
    }

    fn op_split(&mut self) -> Result<(), InterpreterError> {
        let n = self.dstack.pop_int()?;
        let c = self.dstack.pop_byte_array()?;
        if n.to_i32() > c.len() as i32 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NumberTooBig,
                "n is larger than length of array".to_string(),
            ));
        }
        if n.less_than_int(0) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NumberTooSmall,
                "n is negative".to_string(),
            ));
        }
        let pos = n.to_int() as usize;
        let a = c[..pos].to_vec();
        let b = c[pos..].to_vec();
        self.dstack.push_byte_array(a);
        self.dstack.push_byte_array(b);
        Ok(())
    }

    fn op_num2bin(&mut self) -> Result<(), InterpreterError> {
        let n = self.dstack.pop_int()?;
        let a = self.dstack.pop_byte_array()?;

        if n.greater_than_int(self.cfg.max_script_element_size() as i64) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NumberTooBig,
                format!("n is larger than the max of {}", self.cfg.max_script_element_size()),
            ));
        }

        let sn = ScriptNumber::from_bytes(&a, a.len(), false, self.after_genesis)?;
        let mut b = sn.to_bytes();

        if n.less_than_int(b.len() as i64) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NumberTooSmall,
                "cannot fit it into n sized array".to_string(),
            ));
        }
        if n.equal_int(b.len() as i64) {
            self.dstack.push_byte_array(b);
            return Ok(());
        }

        let mut signbit: u8 = 0x00;
        if !b.is_empty() {
            signbit = b[b.len() - 1] & 0x80;
            let last = b.len() - 1;
            b[last] &= 0x7f;
        }

        while n.greater_than_int((b.len() + 1) as i64) {
            b.push(0x00);
        }
        b.push(signbit);

        self.dstack.push_byte_array(b);
        Ok(())
    }

    fn op_bin2num(&mut self) -> Result<(), InterpreterError> {
        let a = self.dstack.pop_byte_array()?;
        let b = minimally_encode(&a);
        if b.len() > self.cfg.max_script_number_length() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NumberTooBig,
                format!(
                    "script numbers are limited to {} bytes",
                    self.cfg.max_script_number_length()
                ),
            ));
        }
        self.dstack.push_byte_array(b);
        Ok(())
    }

    fn op_size(&mut self) -> Result<(), InterpreterError> {
        let so = self.dstack.peek_byte_array(0)?;
        self.dstack
            .push_int(&ScriptNumber::new(so.len() as i64, self.after_genesis));
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Bitwise operations
    // -----------------------------------------------------------------------

    fn op_invert(&mut self) -> Result<(), InterpreterError> {
        let ba = self.dstack.pop_byte_array()?;
        let inverted: Vec<u8> = ba.iter().map(|b| b ^ 0xFF).collect();
        self.dstack.push_byte_array(inverted);
        Ok(())
    }

    fn op_bitwise(&mut self, f: fn(u8, u8) -> u8) -> Result<(), InterpreterError> {
        let a = self.dstack.pop_byte_array()?;
        let b = self.dstack.pop_byte_array()?;
        if a.len() != b.len() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidInputLength,
                "byte arrays are not the same length".to_string(),
            ));
        }
        let c: Vec<u8> = a.iter().zip(b.iter()).map(|(&x, &y)| f(x, y)).collect();
        self.dstack.push_byte_array(c);
        Ok(())
    }

    fn op_equal(&mut self) -> Result<(), InterpreterError> {
        let a = self.dstack.pop_byte_array()?;
        let b = self.dstack.pop_byte_array()?;
        self.dstack.push_bool(a == b);
        Ok(())
    }

    fn op_equalverify(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        self.op_equal()?;
        self.abstract_verify(pop, InterpreterErrorCode::EqualVerify)
    }

    // -----------------------------------------------------------------------
    // Arithmetic operations
    // -----------------------------------------------------------------------

    fn op_unary_int(&mut self, f: impl FnOnce(&mut ScriptNumber)) -> Result<(), InterpreterError> {
        let mut m = self.dstack.pop_int()?;
        f(&mut m);
        self.dstack.push_int(&m);
        Ok(())
    }

    fn op_not(&mut self) -> Result<(), InterpreterError> {
        let m = self.dstack.pop_int()?;
        let n = if m.is_zero() { 1i64 } else { 0 };
        self.dstack
            .push_int(&ScriptNumber::new(n, self.after_genesis));
        Ok(())
    }

    fn op_0notequal(&mut self) -> Result<(), InterpreterError> {
        let mut m = self.dstack.pop_int()?;
        if !m.is_zero() {
            m.set(1);
        }
        self.dstack.push_int(&m);
        Ok(())
    }

    fn op_add(&mut self) -> Result<(), InterpreterError> {
        let mut v0 = self.dstack.pop_int()?;
        let v1 = self.dstack.pop_int()?;
        v0.add(&v1);
        self.dstack.push_int(&v0);
        Ok(())
    }

    fn op_sub(&mut self) -> Result<(), InterpreterError> {
        let v0 = self.dstack.pop_int()?;
        let mut v1 = self.dstack.pop_int()?;
        v1.sub(&v0);
        self.dstack.push_int(&v1);
        Ok(())
    }

    fn op_mul(&mut self) -> Result<(), InterpreterError> {
        let mut n1 = self.dstack.pop_int()?;
        let n2 = self.dstack.pop_int()?;
        n1.mul(&n2);
        self.dstack.push_int(&n1);
        Ok(())
    }

    fn op_div(&mut self) -> Result<(), InterpreterError> {
        let b = self.dstack.pop_int()?;
        let mut a = self.dstack.pop_int()?;
        if b.is_zero() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::DivideByZero,
                "divide by zero".to_string(),
            ));
        }
        a.div(&b);
        self.dstack.push_int(&a);
        Ok(())
    }

    fn op_mod(&mut self) -> Result<(), InterpreterError> {
        let b = self.dstack.pop_int()?;
        let mut a = self.dstack.pop_int()?;
        if b.is_zero() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::DivideByZero,
                "mod by zero".to_string(),
            ));
        }
        a.modulo(&b);
        self.dstack.push_int(&a);
        Ok(())
    }

    fn op_lshift(&mut self) -> Result<(), InterpreterError> {
        let num = self.dstack.pop_int()?;
        let n = num.to_int() as usize;
        if (num.to_int()) < 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NumberTooSmall,
                "n less than 0".to_string(),
            ));
        }
        let x = self.dstack.pop_byte_array()?;

        let bit_shift = n % 8;
        let byte_shift = n / 8;
        let masks: [u8; 8] = [0xFF, 0x7F, 0x3F, 0x1F, 0x0F, 0x07, 0x03, 0x01];
        let mask = masks[bit_shift];
        let overflow_mask = !mask;

        let mut result = vec![0u8; x.len()];
        for idx in (1..=x.len()).rev() {
            let i = idx - 1;
            if byte_shift <= i {
                let k = i - byte_shift;
                let val = (x[i] & mask) << bit_shift;
                result[k] |= val;
                if k >= 1 {
                    let carry = (x[i] & overflow_mask) >> (8 - bit_shift);
                    result[k - 1] |= carry;
                }
            }
        }
        self.dstack.push_byte_array(result);
        Ok(())
    }

    fn op_rshift(&mut self) -> Result<(), InterpreterError> {
        let num = self.dstack.pop_int()?;
        let n = num.to_int() as usize;
        if (num.to_int()) < 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::NumberTooSmall,
                "n less than 0".to_string(),
            ));
        }
        let x = self.dstack.pop_byte_array()?;

        let byte_shift = n / 8;
        let bit_shift = n % 8;
        let masks: [u8; 8] = [0xFF, 0xFE, 0xFC, 0xF8, 0xF0, 0xE0, 0xC0, 0x80];
        let mask = masks[bit_shift];
        let overflow_mask = !mask;

        let mut result = vec![0u8; x.len()];
        for (i, &b) in x.iter().enumerate() {
            let k = i + byte_shift;
            if k < x.len() {
                let val = (b & mask) >> bit_shift;
                result[k] |= val;
            }
            if k + 1 < x.len() {
                let carry = (b & overflow_mask) << (8 - bit_shift);
                result[k + 1] |= carry;
            }
        }
        self.dstack.push_byte_array(result);
        Ok(())
    }

    /// Binary op that pops two ints and pushes a bool result.
    /// Note: v0 is top of stack (popped first), v1 is second-to-top.
    /// The comparisons are: v1 OP v0 (matching Go's behavior).
    fn op_bool_binop(
        &mut self,
        f: impl FnOnce(&ScriptNumber, &ScriptNumber) -> bool,
    ) -> Result<(), InterpreterError> {
        let v0 = self.dstack.pop_int()?;
        let v1 = self.dstack.pop_int()?;
        let n = if f(&v1, &v0) { 1i64 } else { 0 };
        self.dstack
            .push_int(&ScriptNumber::new(n, self.after_genesis));
        Ok(())
    }

    fn op_numequalverify(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        self.op_bool_binop(|a, b| a.equal(b))?;
        self.abstract_verify(pop, InterpreterErrorCode::NumEqualVerify)
    }

    fn op_min(&mut self) -> Result<(), InterpreterError> {
        let v0 = self.dstack.pop_int()?;
        let v1 = self.dstack.pop_int()?;
        if v1.less_than(&v0) {
            self.dstack.push_int(&v1);
        } else {
            self.dstack.push_int(&v0);
        }
        Ok(())
    }

    fn op_max(&mut self) -> Result<(), InterpreterError> {
        let v0 = self.dstack.pop_int()?;
        let v1 = self.dstack.pop_int()?;
        if v1.greater_than(&v0) {
            self.dstack.push_int(&v1);
        } else {
            self.dstack.push_int(&v0);
        }
        Ok(())
    }

    fn op_within(&mut self) -> Result<(), InterpreterError> {
        let max_val = self.dstack.pop_int()?;
        let min_val = self.dstack.pop_int()?;
        let x = self.dstack.pop_int()?;
        let n = if min_val.less_than_or_equal(&x) && x.less_than(&max_val) {
            1i64
        } else {
            0
        };
        self.dstack
            .push_int(&ScriptNumber::new(n, self.after_genesis));
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Hash operations
    // -----------------------------------------------------------------------

    fn op_hash(&mut self, hash_type: HashType) -> Result<(), InterpreterError> {
        let buf = self.dstack.pop_byte_array()?;
        let result = match hash_type {
            HashType::Ripemd160 => {
                use ripemd::Ripemd160;
                use sha2::Digest;
                let mut hasher = Ripemd160::new();
                hasher.update(&buf);
                hasher.finalize().to_vec()
            }
            HashType::Sha1 => {
                use sha1::Sha1;
                use sha1::Digest;
                let mut hasher = Sha1::new();
                hasher.update(&buf);
                hasher.finalize().to_vec()
            }
            HashType::Sha256 => {
                use sha2::{Sha256, Digest};
                let mut hasher = Sha256::new();
                hasher.update(&buf);
                hasher.finalize().to_vec()
            }
            HashType::Hash160 => {
                use sha2::{Sha256, Digest as Digest2};
                use ripemd::{Ripemd160, Digest};
                let sha = Sha256::digest(&buf);
                let mut ripe = Ripemd160::new();
                ripe.update(&sha);
                ripe.finalize().to_vec()
            }
            HashType::Hash256 => {
                use sha2::{Sha256, Digest};
                let first = Sha256::digest(&buf);
                let second = Sha256::digest(&first);
                second.to_vec()
            }
        };
        self.dstack.push_byte_array(result);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Signature operations
    // -----------------------------------------------------------------------

    fn sub_script(&self) -> ParsedScript {
        let skip = if self.last_code_sep > 0 {
            self.last_code_sep + 1
        } else {
            0
        };
        self.scripts[self.script_idx][skip..].to_vec()
    }

    fn op_checksig(&mut self) -> Result<(), InterpreterError> {
        let pk_bytes = self.dstack.pop_byte_array()?;
        let full_sig_bytes = self.dstack.pop_byte_array()?;

        if full_sig_bytes.is_empty() {
            self.dstack.push_bool(false);
            return Ok(());
        }

        let ctx = self.tx_context.ok_or_else(|| {
            InterpreterError::new(
                InterpreterErrorCode::InvalidParams,
                "no tx context for checksig".to_string(),
            )
        })?;

        let shf = *full_sig_bytes.last().unwrap() as u32;
        let sig_bytes = &full_sig_bytes[..full_sig_bytes.len() - 1];

        // Check encodings
        self.check_hash_type_encoding(shf)?;
        self.check_signature_encoding(sig_bytes)?;
        self.check_pub_key_encoding(&pk_bytes)?;

        // Get subscript
        let mut sub_script = self.sub_script();

        // Remove signature from subscript for non-forkid
        let has_forkid = self.has_flag(ScriptFlags::ENABLE_SIGHASH_FORKID)
            && (shf & 0x40) != 0; // SIGHASH_FORKID = 0x40
        if !has_forkid {
            sub_script = remove_opcode_by_data(&sub_script, &full_sig_bytes);
            sub_script = remove_opcode(&sub_script, OP_CODESEPARATOR);
        }

        let script_bytes = unparse(&sub_script);

        match ctx.verify_signature(&full_sig_bytes, &pk_bytes, &script_bytes, self.input_idx, shf) {
            Ok(valid) => {
                if !valid
                    && self.has_flag(ScriptFlags::VERIFY_NULL_FAIL)
                    && !sig_bytes.is_empty()
                {
                    return Err(InterpreterError::new(
                        InterpreterErrorCode::NullFail,
                        "signature not empty on failed checksig".to_string(),
                    ));
                }
                self.dstack.push_bool(valid);
                Ok(())
            }
            Err(_) => {
                self.dstack.push_bool(false);
                Ok(())
            }
        }
    }

    fn op_checksigverify(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        self.op_checksig()?;
        self.abstract_verify(pop, InterpreterErrorCode::CheckSigVerify)
    }

    fn op_checkmultisig(&mut self) -> Result<(), InterpreterError> {
        let num_keys = self.dstack.pop_int()?;
        let num_pub_keys = num_keys.to_int() as i32;

        if num_pub_keys < 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidPubKeyCount,
                format!("number of pubkeys {} is negative", num_pub_keys),
            ));
        }
        if num_pub_keys as usize > self.cfg.max_pub_keys_per_multisig() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidPubKeyCount,
                format!(
                    "too many pubkeys: {} > {}",
                    num_pub_keys,
                    self.cfg.max_pub_keys_per_multisig()
                ),
            ));
        }

        self.num_ops += num_pub_keys as usize;
        if self.num_ops > self.cfg.max_ops() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::TooManyOperations,
                format!("exceeded max operation limit of {}", self.cfg.max_ops()),
            ));
        }

        let mut pub_keys = Vec::new();
        for _ in 0..num_pub_keys {
            pub_keys.push(self.dstack.pop_byte_array()?);
        }

        let num_sigs = self.dstack.pop_int()?;
        let num_signatures = num_sigs.to_int() as i32;

        if num_signatures < 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidSignatureCount,
                format!("number of signatures {} is negative", num_signatures),
            ));
        }
        if num_signatures > num_pub_keys {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidSignatureCount,
                format!(
                    "more signatures than pubkeys: {} > {}",
                    num_signatures, num_pub_keys
                ),
            ));
        }

        let mut signatures: Vec<Vec<u8>> = Vec::new();
        for _ in 0..num_signatures {
            signatures.push(self.dstack.pop_byte_array()?);
        }

        // Dummy element (Satoshi bug)
        let dummy = self.dstack.pop_byte_array()?;
        if self.has_flag(ScriptFlags::STRICT_MULTI_SIG) && !dummy.is_empty() {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigNullDummy,
                format!(
                    "multisig dummy argument has length {} instead of 0",
                    dummy.len()
                ),
            ));
        }

        // Get subscript
        let mut scr = self.sub_script();
        for sig in &signatures {
            scr = remove_opcode_by_data(&scr, sig);
            scr = remove_opcode(&scr, OP_CODESEPARATOR);
        }

        let ctx = match self.tx_context {
            Some(c) => c,
            None => {
                self.dstack.push_bool(false);
                return Ok(());
            }
        };

        let script_bytes = unparse(&scr);
        let mut success = true;
        let mut remaining_keys = num_pub_keys + 1;
        let mut pub_key_idx: i32 = -1;
        let mut sig_idx: usize = 0;
        let mut remaining_sigs = num_signatures;

        while remaining_sigs > 0 {
            pub_key_idx += 1;
            remaining_keys -= 1;

            if remaining_sigs > remaining_keys {
                success = false;
                break;
            }

            let sig = &signatures[sig_idx];
            let pub_key = &pub_keys[pub_key_idx as usize];

            if sig.is_empty() {
                continue;
            }

            let shf = *sig.last().unwrap() as u32;
            let sig_only = &sig[..sig.len() - 1];

            // Check encodings
            if let Err(e) = self.check_hash_type_encoding(shf) {
                return Err(e);
            }
            if let Err(e) = self.check_signature_encoding(sig_only) {
                return Err(e);
            }
            if let Err(e) = self.check_pub_key_encoding(pub_key) {
                return Err(e);
            }

            match ctx.verify_signature(sig, pub_key, &script_bytes, self.input_idx, shf) {
                Ok(true) => {
                    sig_idx += 1;
                    remaining_sigs -= 1;
                }
                _ => {}
            }
        }

        if !success && self.has_flag(ScriptFlags::VERIFY_NULL_FAIL) {
            for sig in &signatures {
                if !sig.is_empty() {
                    return Err(InterpreterError::new(
                        InterpreterErrorCode::NullFail,
                        "not all signatures empty on failed checkmultisig".to_string(),
                    ));
                }
            }
        }

        self.dstack.push_bool(success);
        Ok(())
    }

    fn op_checkmultisigverify(&mut self, pop: &ParsedOpcode) -> Result<(), InterpreterError> {
        self.op_checkmultisig()?;
        self.abstract_verify(pop, InterpreterErrorCode::CheckMultiSigVerify)
    }

    // -----------------------------------------------------------------------
    // Encoding checks
    // -----------------------------------------------------------------------

    fn check_hash_type_encoding(&self, shf: u32) -> Result<(), InterpreterError> {
        if !self.has_flag(ScriptFlags::VERIFY_STRICT_ENCODING) {
            return Ok(());
        }

        let sighash_forkid: u32 = 0x40;
        let sighash_anyonecanpay: u32 = 0x80;

        let mut sig_hash_type = shf & !sighash_anyonecanpay;

        if self.has_flag(ScriptFlags::VERIFY_BIP143_SIGHASH) {
            sig_hash_type ^= sighash_forkid;
            if shf & sighash_forkid == 0 {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::InvalidSigHashType,
                    format!("hash type does not contain uahf forkID 0x{:x}", shf),
                ));
            }
        }

        if sig_hash_type & sighash_forkid == 0 {
            // Non-forkid
            if sig_hash_type < 1 || sig_hash_type > 3 {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::InvalidSigHashType,
                    format!("invalid hash type 0x{:x}", shf),
                ));
            }
            return Ok(());
        }

        // Has forkid
        let base = sig_hash_type & !sighash_forkid;
        if base < 1 || base > 3 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::InvalidSigHashType,
                format!("invalid hash type 0x{:x}", shf),
            ));
        }

        if !self.has_flag(ScriptFlags::ENABLE_SIGHASH_FORKID) && (shf & sighash_forkid != 0) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::IllegalForkID,
                "fork id sighash set without flag".to_string(),
            ));
        }
        if self.has_flag(ScriptFlags::ENABLE_SIGHASH_FORKID) && (shf & sighash_forkid == 0) {
            return Err(InterpreterError::new(
                InterpreterErrorCode::IllegalForkID,
                "fork id sighash not set with flag".to_string(),
            ));
        }

        Ok(())
    }

    fn check_pub_key_encoding(&self, pub_key: &[u8]) -> Result<(), InterpreterError> {
        if !self.has_flag(ScriptFlags::VERIFY_STRICT_ENCODING) {
            return Ok(());
        }
        if pub_key.len() == 33 && (pub_key[0] == 0x02 || pub_key[0] == 0x03) {
            return Ok(());
        }
        if pub_key.len() == 65 && pub_key[0] == 0x04 {
            return Ok(());
        }
        Err(InterpreterError::new(
            InterpreterErrorCode::PubKeyType,
            "unsupported public key type".to_string(),
        ))
    }

    fn check_signature_encoding(&self, sig: &[u8]) -> Result<(), InterpreterError> {
        if !self.has_any(&[
            ScriptFlags::VERIFY_DER_SIGNATURES,
            ScriptFlags::VERIFY_LOW_S,
            ScriptFlags::VERIFY_STRICT_ENCODING,
        ]) {
            return Ok(());
        }

        if sig.is_empty() {
            return Ok(());
        }

        // DER format checks
        let sig_len = sig.len();
        if sig_len < 8 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigTooShort,
                format!("malformed signature: too short: {} < 8", sig_len),
            ));
        }
        if sig_len > 72 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigTooLong,
                format!("malformed signature: too long: {} > 72", sig_len),
            ));
        }
        if sig[0] != 0x30 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigInvalidSeqID,
                format!("malformed signature: format has wrong type: {:#x}", sig[0]),
            ));
        }
        if sig[1] as usize != sig_len - 2 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigInvalidDataLen,
                format!(
                    "malformed signature: bad length: {} != {}",
                    sig[1],
                    sig_len - 2
                ),
            ));
        }

        let r_len = sig[3] as usize;
        let s_type_offset = 4 + r_len;
        let s_len_offset = s_type_offset + 1;

        if s_type_offset >= sig_len {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigMissingSTypeID,
                "malformed signature: S type indicator missing".to_string(),
            ));
        }
        if s_len_offset >= sig_len {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigMissingSLen,
                "malformed signature: S length missing".to_string(),
            ));
        }

        let s_offset = s_len_offset + 1;
        let s_len = sig[s_len_offset] as usize;
        if s_offset + s_len != sig_len {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigInvalidSLen,
                "malformed signature: invalid S length".to_string(),
            ));
        }

        if sig[2] != 0x02 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigInvalidRIntID,
                format!(
                    "malformed signature: R integer marker: {:#x} != 0x02",
                    sig[2]
                ),
            ));
        }
        if r_len == 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigZeroRLen,
                "malformed signature: R length is zero".to_string(),
            ));
        }
        if sig[4] & 0x80 != 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigNegativeR,
                "malformed signature: R is negative".to_string(),
            ));
        }
        if r_len > 1 && sig[4] == 0x00 && sig[5] & 0x80 == 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigTooMuchRPadding,
                "malformed signature: R value has too much padding".to_string(),
            ));
        }

        if sig[s_type_offset] != 0x02 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigInvalidSIntID,
                format!(
                    "malformed signature: S integer marker: {:#x} != 0x02",
                    sig[s_type_offset]
                ),
            ));
        }
        if s_len == 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigZeroSLen,
                "malformed signature: S length is zero".to_string(),
            ));
        }
        if sig[s_offset] & 0x80 != 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigNegativeS,
                "malformed signature: S is negative".to_string(),
            ));
        }
        if s_len > 1 && sig[s_offset] == 0x00 && sig[s_offset + 1] & 0x80 == 0 {
            return Err(InterpreterError::new(
                InterpreterErrorCode::SigTooMuchSPadding,
                "malformed signature: S value has too much padding".to_string(),
            ));
        }

        // Low-S check
        if self.has_flag(ScriptFlags::VERIFY_LOW_S) {
            // Half order of secp256k1
            let half_order = BigInt::parse_bytes(
                b"7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0",
                16,
            )
            .unwrap();
            let s_value = BigInt::from_bytes_be(
                num_bigint::Sign::Plus,
                &sig[s_offset..s_offset + s_len],
            );
            if s_value > half_order {
                return Err(InterpreterError::new(
                    InterpreterErrorCode::SigHighS,
                    "signature is not canonical due to unnecessarily high S value".to_string(),
                ));
            }
        }

        Ok(())
    }
}

enum HashType {
    Ripemd160,
    Sha1,
    Sha256,
    Hash160,
    Hash256,
}

fn verify_lock_time(
    tx_lock_time: i64,
    threshold: i64,
    lock_time: i64,
) -> Result<(), InterpreterError> {
    if (tx_lock_time < threshold && lock_time >= threshold)
        || (tx_lock_time >= threshold && lock_time < threshold)
    {
        return Err(InterpreterError::new(
            InterpreterErrorCode::UnsatisfiedLockTime,
            format!(
                "mismatched locktime types -- tx locktime {}, stack locktime {}",
                tx_lock_time, lock_time
            ),
        ));
    }
    if lock_time > tx_lock_time {
        return Err(InterpreterError::new(
            InterpreterErrorCode::UnsatisfiedLockTime,
            format!(
                "locktime requirement not satisfied -- locktime is greater than the transaction locktime: {} > {}",
                lock_time, tx_lock_time
            ),
        ));
    }
    Ok(())
}
