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
    #[error("invalid jump destination: {0}")]
    InvalidJump(usize),
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
        0x02 => "MUL",
        0x03 => "SUB",
        0x04 => "DIV",
        0x06 => "MOD",
        0x10 => "LT",
        0x11 => "GT",
        0x14 => "EQ",
        0x15 => "ISZERO",
        0x16 => "AND",
        0x17 => "OR",
        0x18 => "XOR",
        0x19 => "NOT",
        0x1b => "SHL",
        0x1c => "SHR",
        0x50 => "POP",
        0x51 => "MLOAD",
        0x52 => "MSTORE",
        0x53 => "MSTORE8",
        0x56 => "JUMP",
        0x57 => "JUMPI",
        0x58 => "PC",
        0x59 => "MSIZE",
        0x5b => "JUMPDEST",
        0x5f => "PUSH0",
        0x60..=0x7f => "PUSH",
        0x80..=0x8f => "DUP",
        0x90..=0x9f => "SWAP",
        0xf3 => "RETURN",
        0xb0 => "PQVERIFY",
        0xb1 => "PQHASH",
        0xb2 => "PQADDR",
        0xf2 => "CALLCODE",
        0xfd => "REVERT",
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
                0x01 => self.binary_op(U256::wrapping_add)?,
                0x02 => self.binary_op(U256::wrapping_mul)?,
                0x03 => self.binary_op(|a, b| b.wrapping_sub(a))?,
                0x04 => self.binary_op(|a, b| if a.is_zero() { U256::ZERO } else { b / a })?,
                0x06 => self.binary_op(|a, b| if a.is_zero() { U256::ZERO } else { b % a })?,
                0x10 => self.binary_op(|a, b| U256::from(b < a))?,
                0x11 => self.binary_op(|a, b| U256::from(b > a))?,
                0x14 => self.binary_op(|a, b| U256::from(a == b))?,
                0x15 => {
                    let value = self.pop()?;
                    self.push(U256::from(value.is_zero()))?;
                }
                0x16 => self.binary_op(|a, b| a & b)?,
                0x17 => self.binary_op(|a, b| a | b)?,
                0x18 => self.binary_op(|a, b| a ^ b)?,
                0x19 => {
                    let value = self.pop()?;
                    self.push(!value)?;
                }
                0x1b => self.binary_op(shift_left)?,
                0x1c => self.binary_op(shift_right)?,
                0x50 => {
                    self.pop()?;
                }
                0x51 => {
                    let offset = u256_to_usize(self.pop()?)?;
                    let word = self.memory.load(offset, 32)?;
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(word);
                    self.push(U256::from_be_bytes(bytes))?;
                }
                0x52 => {
                    let offset = u256_to_usize(self.pop()?)?;
                    let value = self.pop()?;
                    let bytes = value.to_be_bytes::<32>();
                    let memory_gas = self.memory.store(offset, &bytes)?;
                    gas.charge(memory_gas)?;
                }
                0x53 => {
                    let offset = u256_to_usize(self.pop()?)?;
                    let value = self.pop()?;
                    let byte = value.to_be_bytes::<32>()[31];
                    let memory_gas = self.memory.store(offset, &[byte])?;
                    gas.charge(memory_gas)?;
                }
                0x56 => {
                    let dest = u256_to_usize(self.pop()?)?;
                    if !bytecode.is_valid_jumpdest(dest) {
                        return Err(InterpreterError::InvalidJump(dest));
                    }
                    pc = dest;
                }
                0x57 => {
                    let dest = u256_to_usize(self.pop()?)?;
                    let condition = self.pop()?;
                    if !condition.is_zero() {
                        if !bytecode.is_valid_jumpdest(dest) {
                            return Err(InterpreterError::InvalidJump(dest));
                        }
                        pc = dest;
                    }
                }
                0x58 => self.push(U256::from(pc - 1))?,
                0x59 => self.push(U256::from(self.memory.len()))?,
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
                0x80..=0x8f => {
                    let depth = (opcode - 0x7f) as usize;
                    let value = self.peek(depth)?;
                    self.push(value)?;
                }
                0x90..=0x9f => {
                    let depth = (opcode - 0x8f) as usize;
                    self.swap(depth)?;
                }
                0xf2 => return Err(InterpreterError::RemovedOpcode("CALLCODE")),
                0xf3 => {
                    let offset = u256_to_usize(self.pop()?)?;
                    let len = u256_to_usize(self.pop()?)?;
                    let memory_gas = self.memory.resize_for_access(offset, len)?;
                    gas.charge(memory_gas)?;
                    let output = Bytes::copy_from_slice(self.memory.load(offset, len)?);
                    return Ok(ExecutionResult {
                        status: ExecutionStatus::Success,
                        gas_used: gas.used(),
                        output,
                    });
                }
                0xfd => {
                    let offset = u256_to_usize(self.pop()?)?;
                    let len = u256_to_usize(self.pop()?)?;
                    let memory_gas = self.memory.resize_for_access(offset, len)?;
                    gas.charge(memory_gas)?;
                    let output = Bytes::copy_from_slice(self.memory.load(offset, len)?);
                    return Ok(ExecutionResult {
                        status: ExecutionStatus::Revert,
                        gas_used: gas.used(),
                        output,
                    });
                }
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

    fn peek(&self, depth: usize) -> Result<U256, InterpreterError> {
        self.stack
            .get(
                self.stack
                    .len()
                    .checked_sub(depth)
                    .ok_or(InterpreterError::StackUnderflow)?,
            )
            .copied()
            .ok_or(InterpreterError::StackUnderflow)
    }

    fn swap(&mut self, depth: usize) -> Result<(), InterpreterError> {
        let top = self
            .stack
            .len()
            .checked_sub(1)
            .ok_or(InterpreterError::StackUnderflow)?;
        let other = self
            .stack
            .len()
            .checked_sub(depth + 1)
            .ok_or(InterpreterError::StackUnderflow)?;
        self.stack.swap(top, other);
        Ok(())
    }

    fn binary_op(&mut self, op: impl FnOnce(U256, U256) -> U256) -> Result<(), InterpreterError> {
        let a = self.pop()?;
        let b = self.pop()?;
        self.push(op(a, b))
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

fn shift_left(shift: U256, value: U256) -> U256 {
    if shift >= U256::from(256) {
        U256::ZERO
    } else {
        value << shift.to::<usize>()
    }
}

fn shift_right(shift: U256, value: U256) -> U256 {
    if shift >= U256::from(256) {
        U256::ZERO
    } else {
        value >> shift.to::<usize>()
    }
}

fn u256_to_usize(value: U256) -> Result<usize, InterpreterError> {
    if value > U256::from(usize::MAX) {
        return Err(InterpreterError::MemoryOverflow);
    }
    Ok(value.to::<usize>())
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
    fn arithmetic_and_bitwise_opcodes_work() {
        let mut db = EmptyDb;
        let mut interpreter = Interpreter::default();
        interpreter
            .execute(
                &mut db,
                &env(),
                &tx(&[
                    0x60, 0x0f, // PUSH1 15
                    0x60, 0x03, // PUSH1 3
                    0x03, // SUB = 12
                    0x60, 0x02, // PUSH1 2
                    0x02, // MUL = 24
                    0x60, 0x18, // PUSH1 24
                    0x14, // EQ = 1
                    0x60, 0x0f, // PUSH1 15
                    0x16, // AND = 1
                    0x00,
                ]),
            )
            .unwrap();

        assert_eq!(interpreter.pop().unwrap(), U256::from(1));
    }

    #[test]
    fn dup_swap_and_pop_work() {
        let mut db = EmptyDb;
        let mut interpreter = Interpreter::default();
        interpreter
            .execute(
                &mut db,
                &env(),
                &tx(&[
                    0x60, 0x01, // PUSH1 1
                    0x60, 0x02, // PUSH1 2
                    0x80, // DUP1 -> 1,2,2
                    0x90, // SWAP1 -> 1,2,2
                    0x50, // POP -> 1,2
                    0x00,
                ]),
            )
            .unwrap();

        assert_eq!(interpreter.pop().unwrap(), U256::from(2));
        assert_eq!(interpreter.pop().unwrap(), U256::from(1));
    }

    #[test]
    fn memory_store_load_and_return_work() {
        let mut db = EmptyDb;
        let mut interpreter = Interpreter::default();
        let result = interpreter
            .execute(
                &mut db,
                &env(),
                &tx(&[
                    0x60, 0x2a, // PUSH1 42
                    0x60, 0x00, // PUSH1 offset 0
                    0x52, // MSTORE
                    0x60, 0x20, // PUSH1 len 32
                    0x60, 0x00, // PUSH1 offset 0
                    0xf3, // RETURN
                ]),
            )
            .unwrap();

        assert_eq!(result.status, ExecutionStatus::Success);
        assert_eq!(result.output.len(), 32);
        assert_eq!(result.output[31], 0x2a);
    }

    #[test]
    fn jump_and_jumpi_validate_jumpdest() {
        let mut db = EmptyDb;
        let mut interpreter = Interpreter::default();
        interpreter
            .execute(
                &mut db,
                &env(),
                &tx(&[
                    0x60, 0x05, // PUSH1 dest
                    0x56, // JUMP
                    0x00, // skipped
                    0x00, // skipped
                    0x5b, // JUMPDEST
                    0x60, 0x01, // PUSH1 1
                    0x60, 0x0c, // PUSH1 dest
                    0x57, // JUMPI
                    0x00, // skipped
                    0x5b, // JUMPDEST
                    0x60, 0x2a, // PUSH1 42
                    0x00,
                ]),
            )
            .unwrap();

        assert_eq!(interpreter.pop().unwrap(), U256::from(42));
    }

    #[test]
    fn invalid_jump_is_rejected() {
        let mut db = EmptyDb;
        let mut interpreter = Interpreter::default();
        let err = interpreter
            .execute(&mut db, &env(), &tx(&[0x60, 0x03, 0x56, 0x00]))
            .unwrap_err();

        assert!(matches!(err, InterpreterError::InvalidJump(3)));
    }

    #[test]
    fn revert_returns_output_with_revert_status() {
        let mut db = EmptyDb;
        let mut interpreter = Interpreter::default();
        let result = interpreter
            .execute(
                &mut db,
                &env(),
                &tx(&[
                    0x60, 0xee, // PUSH1 0xee
                    0x60, 0x00, // PUSH1 offset 0
                    0x53, // MSTORE8
                    0x60, 0x01, // PUSH1 len 1
                    0x60, 0x00, // PUSH1 offset 0
                    0xfd, // REVERT
                ]),
            )
            .unwrap();

        assert_eq!(result.status, ExecutionStatus::Revert);
        assert_eq!(result.output.as_ref(), &[0xee]);
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
