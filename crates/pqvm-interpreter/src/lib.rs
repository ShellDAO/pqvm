//! PQVM interpreter scaffold.

use alloy_primitives::{Bytes, U256};
use pqvm_primitives::{PQAddress, PQTx};
use pqvm_state::PqvmDatabase;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Env {
    pub chain_id: u64,
    pub block_number: u64,
    pub coinbase: PQAddress,
    pub gas_limit: u64,
    pub timestamp: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionResult {
    pub status: ExecutionStatus,
    pub gas_used: u64,
    pub output: Bytes,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecutionStatus {
    Success,
    Revert,
    Halt,
}

#[derive(Debug, thiserror::Error)]
pub enum InterpreterError {
    #[error("opcode 0x{0:02x} is not implemented yet")]
    UnsupportedOpcode(u8),
    #[error("stack underflow")]
    StackUnderflow,
    #[error("stack overflow")]
    StackOverflow,
}

#[derive(Debug)]
pub struct Interpreter {
    stack: Vec<U256>,
}

impl Default for Interpreter {
    fn default() -> Self {
        Self {
            stack: Vec::with_capacity(1024),
        }
    }
}

impl Interpreter {
    pub fn execute<D: PqvmDatabase>(
        &mut self,
        _db: &mut D,
        _env: &Env,
        tx: &PQTx,
    ) -> Result<ExecutionResult, InterpreterError> {
        if let Some(opcode) = tx.data.first().copied() {
            return Err(InterpreterError::UnsupportedOpcode(opcode));
        }
        Ok(ExecutionResult {
            status: ExecutionStatus::Success,
            gas_used: 0,
            output: Bytes::new(),
        })
    }

    pub fn push(&mut self, value: U256) -> Result<(), InterpreterError> {
        if self.stack.len() >= 1024 {
            return Err(InterpreterError::StackOverflow);
        }
        self.stack.push(value);
        Ok(())
    }

    pub fn pop(&mut self) -> Result<U256, InterpreterError> {
        self.stack.pop().ok_or(InterpreterError::StackUnderflow)
    }
}
