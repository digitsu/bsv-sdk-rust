//! Stack manipulation operations for the script interpreter.

use super::error::InterpreterError;
use super::stack::as_bool;
use super::thread::Thread;

impl<'a> Thread<'a> {
    pub(crate) fn op_to_alt_stack(&mut self) -> Result<(), InterpreterError> {
        let data = self.dstack.pop_byte_array()?;
        self.astack.push_byte_array(data);
        Ok(())
    }

    pub(crate) fn op_from_alt_stack(&mut self) -> Result<(), InterpreterError> {
        let data = self.astack.pop_byte_array()?;
        self.dstack.push_byte_array(data);
        Ok(())
    }

    pub(crate) fn op_ifdup(&mut self) -> Result<(), InterpreterError> {
        let so = self.dstack.peek_byte_array(0)?;
        if as_bool(&so) {
            self.dstack.push_byte_array(so);
        }
        Ok(())
    }

    pub(crate) fn op_pick(&mut self) -> Result<(), InterpreterError> {
        let val = self.dstack.pop_int()?;
        self.dstack.pick_n(val.to_i32())
    }

    pub(crate) fn op_roll(&mut self) -> Result<(), InterpreterError> {
        let val = self.dstack.pop_int()?;
        self.dstack.roll_n(val.to_i32())
    }
}
