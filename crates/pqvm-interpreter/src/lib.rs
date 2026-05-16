//! PQVM interpreter scaffold.

use alloy_primitives::{Bytes, U256};
use pqvm_primitives::{PQAddress, PQTx};
use pqvm_state::PqvmDatabase;
use std::collections::BTreeSet;

const GAS_VERYLOW: u64 = 1;
const MEMORY_LINEAR_GAS: u64 = 3;
const MEMORY_QUAD_DENOMINATOR: u64 = 512;

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
    #[error("out of gas: required {required}, remaining {remaining}")]
    OutOfGas { required: u64, remaining: u64 },
    #[error("memory access overflows usize")]
    MemoryOverflow,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GasMeter {
    limit: u64,
    used: u64,
}

impl GasMeter {
    pub const fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    pub const fn limit(&self) -> u64 {
        self.limit
    }

    pub const fn used(&self) -> u64 {
        self.used
    }

    pub const fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    pub fn charge(&mut self, amount: u64) -> Result<(), InterpreterError> {
        if amount > self.remaining() {
            return Err(InterpreterError::OutOfGas {
                required: amount,
                remaining: self.remaining(),
            });
        }
        self.used += amount;
        Ok(())
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Memory {
    bytes: Vec<u8>,
}

impl Memory {
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn load(&mut self, offset: usize, len: usize) -> Result<&[u8], InterpreterError> {
        self.resize_for_access(offset, len)?;
        Ok(&self.bytes[offset..offset + len])
    }

    pub fn store(&mut self, offset: usize, data: &[u8]) -> Result<u64, InterpreterError> {
        let cost = self.resize_for_access(offset, data.len())?;
        self.bytes[offset..offset + data.len()].copy_from_slice(data);
        Ok(cost)
    }

    pub fn resize_for_access(
        &mut self,
        offset: usize,
        len: usize,
    ) -> Result<u64, InterpreterError> {
        let Some(end) = offset.checked_add(len) else {
            return Err(InterpreterError::MemoryOverflow);
        };
        if end <= self.bytes.len() {
            return Ok(0);
        }

        let old_words = words_for_len(self.bytes.len())?;
        let new_words = words_for_len(end)?;
        let cost = memory_expansion_cost(old_words, new_words);
        self.bytes.resize(new_words * 32, 0);
        Ok(cost)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bytecode<'a> {
    code: &'a [u8],
    jumpdests: BTreeSet<usize>,
}

impl<'a> Bytecode<'a> {
    pub fn new(code: &'a [u8]) -> Self {
        Self {
            code,
            jumpdests: analyze_jumpdests(code),
        }
    }

    pub const fn as_slice(&self) -> &'a [u8] {
        self.code
    }

    pub fn is_valid_jumpdest(&self, pc: usize) -> bool {
        self.jumpdests.contains(&pc)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpcodeInfo {
    pub byte: u8,
    pub name: &'static str,
    pub base_gas: u64,
}

pub fn opcode_info(opcode: u8) -> Option<OpcodeInfo> {
    let name = match opcode {
        0x00 => "STOP",
        0x01 => "ADD",
        0x5b => "JUMPDEST",
        0x5f => "PUSH0",
        0x60..=0x7f => "PUSH",
        0xb0 => "PQVERIFY",
        0xb1 => "PQHASH",
        0xb2 => "PQADDR",
        0xf2 => "CALLCODE",
        _ => return None,
    };

    Some(OpcodeInfo {
        byte: opcode,
        name,
        base_gas: GAS_VERYLOW,
    })
}

#[derive(Debug)]
pub struct Interpreter {
    stack: Vec<U256>,
    memory: Memory,
}

impl Default for Interpreter {
    fn default() -> Self {
        Self {
            stack: Vec::with_capacity(1024),
            memory: Memory::default(),
        }
    }
}

impl Interpreter {
    pub fn execute<D: PqvmDatabase>(
        &mut self,
        _db: &mut D,
        env: &Env,
        tx: &PQTx,
    ) -> Result<ExecutionResult, InterpreterError> {
        let bytecode = Bytecode::new(tx.data.as_ref());
        let code = bytecode.as_slice();
        let mut pc = 0usize;
        let mut gas = GasMeter::new(tx.gas_limit.min(env.gas_limit));

        while pc < code.len() {
            let opcode = code[pc];
            pc += 1;
            gas.charge(opcode_info(opcode).map_or(GAS_VERYLOW, |info| info.base_gas))?;

            match opcode {
                0x00 => {
                    return Ok(ExecutionResult {
                        status: ExecutionStatus::Success,
                        gas_used: gas.used(),
                        output: Bytes::new(),
                    });
                }
                0x01 => {
                    let a = self.pop()?;
                    let b = self.pop()?;
                    self.push(a.wrapping_add(b))?;
                }
                0x5b => {}
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
            gas_used: gas.used(),
            output: Bytes::new(),
        })
    }

    pub fn memory(&self) -> &Memory {
        &self.memory
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

fn analyze_jumpdests(code: &[u8]) -> BTreeSet<usize> {
    let mut jumpdests = BTreeSet::new();
    let mut pc = 0usize;

    while pc < code.len() {
        let opcode = code[pc];
        if opcode == 0x5b {
            jumpdests.insert(pc);
        }

        pc += 1;
        if (0x60..=0x7f).contains(&opcode) {
            pc = pc.saturating_add((opcode - 0x5f) as usize);
        }
    }

    jumpdests
}

fn words_for_len(len: usize) -> Result<usize, InterpreterError> {
    len.checked_add(31)
        .map(|value| value / 32)
        .ok_or(InterpreterError::MemoryOverflow)
}

fn memory_expansion_cost(old_words: usize, new_words: usize) -> u64 {
    if new_words <= old_words {
        return 0;
    }

    memory_cost(new_words as u64) - memory_cost(old_words as u64)
}

fn memory_cost(words: u64) -> u64 {
    MEMORY_LINEAR_GAS * words + words.saturating_mul(words) / MEMORY_QUAD_DENOMINATOR
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

    #[test]
    fn gas_meter_reports_out_of_gas() {
        let mut gas = GasMeter::new(2);
        gas.charge(2).unwrap();
        let err = gas.charge(1).unwrap_err();
        assert!(matches!(
            err,
            InterpreterError::OutOfGas {
                required: 1,
                remaining: 0
            }
        ));
    }

    #[test]
    fn execute_enforces_tx_gas_limit() {
        let mut db = EmptyDb;
        let mut interpreter = Interpreter::default();
        let mut tx = tx(&[0x60, 0x01, 0x00]);
        tx.gas_limit = 1;
        let err = interpreter.execute(&mut db, &env(), &tx).unwrap_err();
        assert!(matches!(err, InterpreterError::OutOfGas { .. }));
    }

    #[test]
    fn memory_expands_in_words_and_preserves_data() {
        let mut memory = Memory::default();
        let cost = memory.store(31, &[0xaa, 0xbb]).unwrap();

        assert_eq!(memory.len(), 64);
        assert_eq!(cost, 6);
        assert_eq!(memory.load(31, 2).unwrap(), &[0xaa, 0xbb]);
    }

    #[test]
    fn jumpdest_analysis_skips_push_immediates() {
        let bytecode = Bytecode::new(&[0x60, 0x5b, 0x5b, 0x00]);

        assert!(!bytecode.is_valid_jumpdest(1));
        assert!(bytecode.is_valid_jumpdest(2));
    }

    #[test]
    fn opcode_metadata_covers_current_dispatch_surface() {
        assert_eq!(opcode_info(0x00).unwrap().name, "STOP");
        assert_eq!(opcode_info(0x01).unwrap().name, "ADD");
        assert_eq!(opcode_info(0x5f).unwrap().name, "PUSH0");
        assert_eq!(opcode_info(0x60).unwrap().name, "PUSH");
        assert_eq!(opcode_info(0xb0).unwrap().name, "PQVERIFY");
        assert_eq!(opcode_info(0xf2).unwrap().name, "CALLCODE");
        assert!(opcode_info(0xfe).is_none());
    }
}
