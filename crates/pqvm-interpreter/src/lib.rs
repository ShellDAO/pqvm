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
    #[error("opcode {0} is removed from PQVM")]
    RemovedOpcode(&'static str),
    #[error("truncated PUSH opcode 0x{opcode:02x}: needs {needed} immediate bytes")]
    TruncatedPush { opcode: u8, needed: usize },
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
        let code = tx.data.as_ref();
        let mut pc = 0usize;
        let mut gas_used = 0u64;

        while pc < code.len() {
            let opcode = code[pc];
            pc += 1;
            gas_used = gas_used.saturating_add(1);

            match opcode {
                0x00 => {
                    return Ok(ExecutionResult {
                        status: ExecutionStatus::Success,
                        gas_used,
                        output: Bytes::new(),
                    });
                }
                0x01 => {
                    let a = self.pop()?;
                    let b = self.pop()?;
                    self.push(a.wrapping_add(b))?;
                }
                0x5f => self.push(U256::ZERO)?,
                0x60..=0x7f => {
                    let len = (opcode - 0x5f) as usize;
                    if pc + len > code.len() {
                        return Err(InterpreterError::TruncatedPush {
                            opcode,
                            needed: len,
                        });
                    }
                    let mut word = [0u8; 32];
                    word[32 - len..].copy_from_slice(&code[pc..pc + len]);
                    pc += len;
                    self.push(U256::from_be_bytes(word))?;
                }
                0xf2 => return Err(InterpreterError::RemovedOpcode("CALLCODE")),
                other => return Err(InterpreterError::UnsupportedOpcode(other)),
            }
        }

        Ok(ExecutionResult {
            status: ExecutionStatus::Success,
            gas_used,
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

#[derive(Debug, Default)]
#[cfg(test)]
struct EmptyDb;

#[cfg(test)]
impl PqvmDatabase for EmptyDb {
    type Error = std::convert::Infallible;

    fn account(
        &mut self,
        _address: PQAddress,
    ) -> Result<Option<pqvm_state::AccountInfo>, Self::Error> {
        Ok(None)
    }

    fn storage(&mut self, _address: PQAddress, _index: U256) -> Result<U256, Self::Error> {
        Ok(U256::ZERO)
    }

    fn block_hash(&mut self, _number: u64) -> Result<alloy_primitives::B256, Self::Error> {
        Ok(alloy_primitives::B256::ZERO)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;

    fn env() -> Env {
        Env {
            chain_id: 1,
            block_number: 0,
            coinbase: PQAddress::zero(),
            gas_limit: 50_000_000,
            timestamp: 0,
        }
    }

    fn tx(data: &[u8]) -> PQTx {
        PQTx {
            chain_id: 1,
            nonce: 0,
            max_fee: U256::ZERO,
            gas_limit: 50_000_000,
            to: None,
            value: U256::ZERO,
            data: Bytes::copy_from_slice(data),
            sig_type: 0x01,
            public_key: None,
            signature: Bytes::new(),
        }
    }

    #[test]
    fn stop_succeeds() {
        let mut db = EmptyDb;
        let mut interpreter = Interpreter::default();
        let result = interpreter.execute(&mut db, &env(), &tx(&[0x00])).unwrap();
        assert_eq!(result.status, ExecutionStatus::Success);
        assert_eq!(result.gas_used, 1);
    }

    #[test]
    fn push_and_add() {
        let mut db = EmptyDb;
        let mut interpreter = Interpreter::default();
        let result = interpreter
            .execute(&mut db, &env(), &tx(&[0x60, 0x02, 0x60, 0x03, 0x01, 0x00]))
            .unwrap();
        assert_eq!(result.status, ExecutionStatus::Success);
        assert_eq!(interpreter.pop().unwrap(), U256::from(5));
    }

    #[test]
    fn callcode_is_removed() {
        let mut db = EmptyDb;
        let mut interpreter = Interpreter::default();
        let err = interpreter
            .execute(&mut db, &env(), &tx(&[0xf2]))
            .unwrap_err();
        assert!(matches!(err, InterpreterError::RemovedOpcode("CALLCODE")));
    }
}
