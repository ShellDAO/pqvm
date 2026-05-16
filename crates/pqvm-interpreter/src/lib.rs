//! PQVM interpreter scaffold.

use alloy_primitives::{keccak256, Bytes, B256, I256, U256};
use pqvm_gas::{
    GAS_BALANCE, GAS_BASEFEE, GAS_BLOCKHASH, GAS_CALL_BASE, GAS_CALL_NEW_ACCOUNT, GAS_CALL_STIPEND,
    GAS_CALL_VALUE, GAS_CHAINID, GAS_COPY_PER_WORD, GAS_CREATE2_EXTRA_PER_WORD, GAS_CREATE_BASE,
    GAS_CREATE_PER_BYTE, GAS_EXTCODE, GAS_KECCAK256_BASE, GAS_KECCAK256_PER_WORD, GAS_LOG_BASE,
    GAS_LOG_PER_BYTE, GAS_LOG_PER_TOPIC, GAS_SELFBALANCE, GAS_SELFDESTRUCT, GAS_SLOAD,
    GAS_SSTORE_NOOP, GAS_SSTORE_RESET, GAS_SSTORE_SET, GAS_VERYLOW, MAX_CALL_DEPTH, PQADDR_OPCODE,
    PQHASH_OPCODE, PQVERIFY_OPCODE,
};
use pqvm_precompiles::{
    BasicPqPrecompiles, PrecompileSet, BLAKE3_256, ML_DSA_65_VERIFY, PQADDRESS_DERIVE,
    SLH_DSA_SHA2_256F_VERIFY,
};
use pqvm_primitives::{PQAddress, PQTx};
use pqvm_state::{AccountInfo, PqvmDatabase};
use std::collections::BTreeSet;

const MEMORY_LINEAR_GAS: u64 = 3;
const MEMORY_QUAD_DENOMINATOR: u64 = 512;

// ── Public types ──────────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Env {
    pub chain_id: u64,
    pub block_number: u64,
    pub coinbase: PQAddress,
    pub gas_limit: u64,
    pub timestamp: u64,
}

/// Context passed to every call frame.
#[derive(Clone, Debug)]
pub struct FrameContext {
    /// Bytecode being executed.
    pub code: Vec<u8>,
    /// Input data (calldata / initcode).
    pub calldata: Bytes,
    /// Immediate caller address.
    pub caller: PQAddress,
    /// Address of the executing account.
    pub address: PQAddress,
    /// Value attached to this call.
    pub value: U256,
    /// Originating transaction sender.
    pub origin: PQAddress,
    /// Whether state mutations are forbidden.
    pub is_static: bool,
    /// Current call depth (0 = top-level transaction).
    pub depth: usize,
    /// Gas budget for this frame.
    pub gas_limit: u64,
}

impl FrameContext {
    /// Create a top-level frame from a transaction.  `tx.data` is treated as
    /// bytecode (legacy / test-compatible behaviour where code is delivered
    /// inline; `execute_transaction` in the facade passes proper code).
    pub fn from_tx(tx: &PQTx, env: &Env) -> Self {
        Self {
            code: tx.data.to_vec(),
            calldata: tx.data.clone(),
            caller: PQAddress::zero(),
            address: tx.to.unwrap_or_default(),
            value: tx.value,
            origin: PQAddress::zero(),
            is_static: false,
            depth: 0,
            gas_limit: tx.gas_limit.min(env.gas_limit),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub address: PQAddress,
    pub topics: Vec<B256>,
    pub data: Bytes,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionResult {
    pub status: ExecutionStatus,
    pub gas_used: u64,
    pub output: Bytes,
    pub logs: Vec<LogEntry>,
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
    #[error("precompile execution failed: {0}")]
    Precompile(String),
    #[error("state error: {0}")]
    Database(String),
    #[error("call or create inside a static context")]
    StaticViolation,
}

// ── GasMeter ──────────────────────────────────────────────────────────────────

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

// ── Memory ────────────────────────────────────────────────────────────────────

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
        if len == 0 {
            return Ok(0);
        }
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

// ── Bytecode / jumpdest analysis ──────────────────────────────────────────────

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

// ── Opcode metadata ───────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OpcodeInfo {
    pub byte: u8,
    pub name: &'static str,
    pub base_gas: u64,
}

pub fn opcode_info(opcode: u8) -> Option<OpcodeInfo> {
    let (name, base_gas) = match opcode {
        0x00 => ("STOP", GAS_VERYLOW),
        0x01 => ("ADD", GAS_VERYLOW),
        0x02 => ("MUL", GAS_VERYLOW),
        0x03 => ("SUB", GAS_VERYLOW),
        0x04 => ("DIV", GAS_VERYLOW),
        0x05 => ("SDIV", GAS_VERYLOW),
        0x06 => ("MOD", GAS_VERYLOW),
        0x07 => ("SMOD", GAS_VERYLOW),
        0x08 => ("ADDMOD", GAS_VERYLOW),
        0x09 => ("MULMOD", GAS_VERYLOW),
        0x10 => ("LT", GAS_VERYLOW),
        0x11 => ("GT", GAS_VERYLOW),
        0x12 => ("SLT", GAS_VERYLOW),
        0x13 => ("SGT", GAS_VERYLOW),
        0x14 => ("EQ", GAS_VERYLOW),
        0x15 => ("ISZERO", GAS_VERYLOW),
        0x16 => ("AND", GAS_VERYLOW),
        0x17 => ("OR", GAS_VERYLOW),
        0x18 => ("XOR", GAS_VERYLOW),
        0x19 => ("NOT", GAS_VERYLOW),
        0x1a => ("BYTE", GAS_VERYLOW),
        0x1b => ("SHL", GAS_VERYLOW),
        0x1c => ("SHR", GAS_VERYLOW),
        0x1d => ("SAR", GAS_VERYLOW),
        0x20 => ("KECCAK256", GAS_KECCAK256_BASE),
        0x30 => ("ADDRESS", GAS_VERYLOW),
        0x31 => ("BALANCE", GAS_BALANCE),
        0x32 => ("ORIGIN", GAS_VERYLOW),
        0x33 => ("CALLER", GAS_VERYLOW),
        0x34 => ("CALLVALUE", GAS_VERYLOW),
        0x35 => ("CALLDATALOAD", GAS_VERYLOW),
        0x36 => ("CALLDATASIZE", GAS_VERYLOW),
        0x37 => ("CALLDATACOPY", GAS_VERYLOW),
        0x38 => ("CODESIZE", GAS_VERYLOW),
        0x39 => ("CODECOPY", GAS_VERYLOW),
        0x3a => ("GASPRICE", GAS_VERYLOW),
        0x3b => ("EXTCODESIZE", GAS_EXTCODE),
        0x3c => ("EXTCODECOPY", GAS_EXTCODE),
        0x3d => ("RETURNDATASIZE", GAS_VERYLOW),
        0x3e => ("RETURNDATACOPY", GAS_VERYLOW),
        0x3f => ("EXTCODEHASH", GAS_EXTCODE),
        0x40 => ("BLOCKHASH", GAS_BLOCKHASH),
        0x41 => ("COINBASE", GAS_VERYLOW),
        0x42 => ("TIMESTAMP", GAS_VERYLOW),
        0x43 => ("NUMBER", GAS_VERYLOW),
        0x44 => ("PREVRANDAO", GAS_VERYLOW),
        0x45 => ("GASLIMIT", GAS_VERYLOW),
        0x46 => ("CHAINID", GAS_CHAINID),
        0x47 => ("SELFBALANCE", GAS_SELFBALANCE),
        0x48 => ("BASEFEE", GAS_BASEFEE),
        0x50 => ("POP", GAS_VERYLOW),
        0x51 => ("MLOAD", GAS_VERYLOW),
        0x52 => ("MSTORE", GAS_VERYLOW),
        0x53 => ("MSTORE8", GAS_VERYLOW),
        0x54 => ("SLOAD", GAS_SLOAD),
        0x55 => ("SSTORE", GAS_SSTORE_SET),
        0x56 => ("JUMP", GAS_VERYLOW),
        0x57 => ("JUMPI", GAS_VERYLOW),
        0x58 => ("PC", GAS_VERYLOW),
        0x59 => ("MSIZE", GAS_VERYLOW),
        0x5a => ("GAS", GAS_VERYLOW),
        0x5b => ("JUMPDEST", GAS_VERYLOW),
        0x5c => ("TLOAD", GAS_VERYLOW),
        0x5d => ("TSTORE", GAS_VERYLOW),
        0x5f => ("PUSH0", GAS_VERYLOW),
        0x60..=0x7f => ("PUSH", GAS_VERYLOW),
        0x80..=0x8f => ("DUP", GAS_VERYLOW),
        0x90..=0x9f => ("SWAP", GAS_VERYLOW),
        0xa0 => ("LOG0", GAS_LOG_BASE),
        0xa1 => ("LOG1", GAS_LOG_BASE + GAS_LOG_PER_TOPIC),
        0xa2 => ("LOG2", GAS_LOG_BASE + 2 * GAS_LOG_PER_TOPIC),
        0xa3 => ("LOG3", GAS_LOG_BASE + 3 * GAS_LOG_PER_TOPIC),
        0xa4 => ("LOG4", GAS_LOG_BASE + 4 * GAS_LOG_PER_TOPIC),
        0xb0 => ("PQVERIFY", GAS_VERYLOW),
        0xb1 => ("PQHASH", GAS_VERYLOW),
        0xb2 => ("PQADDR", GAS_VERYLOW),
        0xf0 => ("CREATE", GAS_CREATE_BASE),
        0xf1 => ("CALL", GAS_CALL_BASE),
        0xf2 => ("CALLCODE", GAS_VERYLOW),
        0xf3 => ("RETURN", GAS_VERYLOW),
        0xf4 => ("DELEGATECALL", GAS_CALL_BASE),
        0xf5 => ("CREATE2", GAS_CREATE_BASE),
        0xfa => ("STATICCALL", GAS_CALL_BASE),
        0xfd => ("REVERT", GAS_VERYLOW),
        0xff => ("SELFDESTRUCT", GAS_SELFDESTRUCT),
        _ => return None,
    };

    Some(OpcodeInfo {
        byte: opcode,
        name,
        base_gas,
    })
}

// ── Interpreter ───────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct Interpreter {
    pub stack: Vec<U256>,
    pub memory: Memory,
    /// Return data from the most recent sub-call.
    pub returndata: Bytes,
}

impl Default for Interpreter {
    fn default() -> Self {
        Self {
            stack: Vec::with_capacity(1024),
            memory: Memory::default(),
            returndata: Bytes::new(),
        }
    }
}

impl Interpreter {
    /// Execute a transaction with `tx.data` as bytecode (legacy / test-compatible).
    pub fn execute<D: PqvmDatabase>(
        &mut self,
        db: &mut D,
        env: &Env,
        tx: &PQTx,
    ) -> Result<ExecutionResult, InterpreterError> {
        let ctx = FrameContext::from_tx(tx, env);
        self.execute_frame(db, env, &ctx)
    }

    /// Execute an arbitrary call frame (used for proper code/calldata separation
    /// and recursive CALL/CREATE dispatch).
    pub fn execute_frame<D: PqvmDatabase>(
        &mut self,
        db: &mut D,
        env: &Env,
        ctx: &FrameContext,
    ) -> Result<ExecutionResult, InterpreterError> {
        let bytecode = Bytecode::new(&ctx.code);
        let code = ctx.code.as_slice();
        let mut pc = 0usize;
        let mut gas = GasMeter::new(ctx.gas_limit);
        let mut logs: Vec<LogEntry> = Vec::new();

        macro_rules! db_err {
            ($e:expr) => {
                $e.map_err(|e| InterpreterError::Database(e.to_string()))
            };
        }

        while pc < code.len() {
            let opcode = code[pc];
            pc += 1;
            // Charge base gas for this opcode.
            gas.charge(opcode_info(opcode).map_or(GAS_VERYLOW, |info| info.base_gas))?;

            match opcode {
                // ── STOP ──────────────────────────────────────────────────
                0x00 => {
                    return Ok(ExecutionResult {
                        status: ExecutionStatus::Success,
                        gas_used: gas.used(),
                        output: Bytes::new(),
                        logs,
                    });
                }

                // ── Arithmetic ────────────────────────────────────────────
                0x01 => self.binary_op(U256::wrapping_add)?,
                0x02 => self.binary_op(U256::wrapping_mul)?,
                0x03 => self.binary_op(|a, b| b.wrapping_sub(a))?,
                0x04 => self.binary_op(|a, b| if a.is_zero() { U256::ZERO } else { b / a })?,
                0x05 => self.binary_op(|a, b| {
                    if a.is_zero() {
                        return U256::ZERO;
                    }
                    let (a_i, b_i) = (I256::from_raw(a), I256::from_raw(b));
                    b_i.wrapping_div(a_i).into_raw()
                })?,
                0x06 => self.binary_op(|a, b| if a.is_zero() { U256::ZERO } else { b % a })?,
                0x07 => self.binary_op(|a, b| {
                    if a.is_zero() {
                        return U256::ZERO;
                    }
                    let (a_i, b_i) = (I256::from_raw(a), I256::from_raw(b));
                    b_i.wrapping_rem(a_i).into_raw()
                })?,
                0x08 => {
                    let a = self.pop()?;
                    let b = self.pop()?;
                    let n = self.pop()?;
                    self.push(if n.is_zero() {
                        U256::ZERO
                    } else {
                        b.add_mod(a, n)
                    })?;
                }
                0x09 => {
                    let a = self.pop()?;
                    let b = self.pop()?;
                    let n = self.pop()?;
                    self.push(if n.is_zero() {
                        U256::ZERO
                    } else {
                        b.mul_mod(a, n)
                    })?;
                }

                // ── Comparison ────────────────────────────────────────────
                0x10 => self.binary_op(|a, b| U256::from(b < a))?,
                0x11 => self.binary_op(|a, b| U256::from(b > a))?,
                0x12 => self.binary_op(|a, b| U256::from(I256::from_raw(b) < I256::from_raw(a)))?,
                0x13 => self.binary_op(|a, b| U256::from(I256::from_raw(b) > I256::from_raw(a)))?,
                0x14 => self.binary_op(|a, b| U256::from(a == b))?,
                0x15 => {
                    let value = self.pop()?;
                    self.push(U256::from(value.is_zero()))?;
                }

                // ── Bitwise ───────────────────────────────────────────────
                0x16 => self.binary_op(|a, b| a & b)?,
                0x17 => self.binary_op(|a, b| a | b)?,
                0x18 => self.binary_op(|a, b| a ^ b)?,
                0x19 => {
                    let value = self.pop()?;
                    self.push(!value)?;
                }
                0x1a => {
                    let byte_idx = self.pop()?;
                    let value = self.pop()?;
                    let result = if byte_idx < U256::from(32) {
                        let idx = byte_idx.to::<usize>();
                        U256::from(value.to_be_bytes::<32>()[idx])
                    } else {
                        U256::ZERO
                    };
                    self.push(result)?;
                }
                0x1b => self.binary_op(shift_left)?,
                0x1c => self.binary_op(shift_right)?,
                0x1d => self.binary_op(sar)?,

                // ── KECCAK256 ─────────────────────────────────────────────
                0x20 => {
                    let offset = u256_to_usize(self.pop()?)?;
                    let len = u256_to_usize(self.pop()?)?;
                    let mem_gas = self.memory.resize_for_access(offset, len)?;
                    gas.charge(mem_gas)?;
                    let word_cost = words_for_len(len)? as u64 * GAS_KECCAK256_PER_WORD;
                    gas.charge(word_cost)?;
                    let data = self.memory.load(offset, len)?.to_vec();
                    let hash = keccak256(&data);
                    self.push(U256::from_be_bytes(hash.0))?;
                }

                // ── Environment / context ─────────────────────────────────
                0x30 => self.push(pqaddress_to_u256(ctx.address))?,
                0x31 => {
                    let addr = u256_to_pqaddress(self.pop()?);
                    let acct = db_err!(db.account(addr))?;
                    self.push(acct.map_or(U256::ZERO, |a| a.balance))?;
                }
                0x32 => self.push(pqaddress_to_u256(ctx.origin))?,
                0x33 => self.push(pqaddress_to_u256(ctx.caller))?,
                0x34 => self.push(ctx.value)?,
                0x35 => {
                    let i = u256_to_usize(self.pop()?)?;
                    let cd = ctx.calldata.as_ref();
                    let mut word = [0u8; 32];
                    let src = if i < cd.len() {
                        &cd[i..cd.len().min(i + 32)]
                    } else {
                        &[]
                    };
                    word[..src.len()].copy_from_slice(src);
                    self.push(U256::from_be_bytes(word))?;
                }
                0x36 => self.push(U256::from(ctx.calldata.len()))?,
                0x37 => {
                    let dest = u256_to_usize(self.pop()?)?;
                    let src_off = u256_to_usize(self.pop()?)?;
                    let len = u256_to_usize(self.pop()?)?;
                    let word_gas = words_for_len(len)? as u64 * GAS_COPY_PER_WORD;
                    gas.charge(word_gas)?;
                    let mem_gas = self.memory.resize_for_access(dest, len)?;
                    gas.charge(mem_gas)?;
                    let cd = ctx.calldata.as_ref();
                    let mut buf = vec![0u8; len];
                    let avail = cd.len().saturating_sub(src_off);
                    let copy_len = avail.min(len);
                    if copy_len > 0 {
                        buf[..copy_len].copy_from_slice(&cd[src_off..src_off + copy_len]);
                    }
                    self.memory.store(dest, &buf)?;
                }
                0x38 => self.push(U256::from(ctx.code.len()))?,
                0x39 => {
                    let dest = u256_to_usize(self.pop()?)?;
                    let src_off = u256_to_usize(self.pop()?)?;
                    let len = u256_to_usize(self.pop()?)?;
                    let word_gas = words_for_len(len)? as u64 * GAS_COPY_PER_WORD;
                    gas.charge(word_gas)?;
                    let mem_gas = self.memory.resize_for_access(dest, len)?;
                    gas.charge(mem_gas)?;
                    let mut buf = vec![0u8; len];
                    let avail = ctx.code.len().saturating_sub(src_off);
                    let copy_len = avail.min(len);
                    if copy_len > 0 {
                        buf[..copy_len].copy_from_slice(&ctx.code[src_off..src_off + copy_len]);
                    }
                    self.memory.store(dest, &buf)?;
                }
                0x3a => self.push(U256::ZERO)?, // GASPRICE: return 0 (no fee market in this spec)
                0x3b => {
                    let addr = u256_to_pqaddress(self.pop()?);
                    let size = db_err!(db.account(addr))?.map_or(0, |a| a.code.len());
                    self.push(U256::from(size))?;
                }
                0x3c => {
                    let addr = u256_to_pqaddress(self.pop()?);
                    let dest = u256_to_usize(self.pop()?)?;
                    let src_off = u256_to_usize(self.pop()?)?;
                    let len = u256_to_usize(self.pop()?)?;
                    let word_gas = words_for_len(len)? as u64 * GAS_COPY_PER_WORD;
                    gas.charge(word_gas)?;
                    let mem_gas = self.memory.resize_for_access(dest, len)?;
                    gas.charge(mem_gas)?;
                    let ext_code = db_err!(db.account(addr))?
                        .map(|a| a.code.to_vec())
                        .unwrap_or_default();
                    let mut buf = vec![0u8; len];
                    let avail = ext_code.len().saturating_sub(src_off);
                    let copy_len = avail.min(len);
                    if copy_len > 0 {
                        buf[..copy_len].copy_from_slice(&ext_code[src_off..src_off + copy_len]);
                    }
                    self.memory.store(dest, &buf)?;
                }
                0x3d => self.push(U256::from(self.returndata.len()))?,
                0x3e => {
                    let dest = u256_to_usize(self.pop()?)?;
                    let src_off = u256_to_usize(self.pop()?)?;
                    let len = u256_to_usize(self.pop()?)?;
                    let word_gas = words_for_len(len)? as u64 * GAS_COPY_PER_WORD;
                    gas.charge(word_gas)?;
                    let mem_gas = self.memory.resize_for_access(dest, len)?;
                    gas.charge(mem_gas)?;
                    let rd = self.returndata.clone();
                    let avail = rd.len().saturating_sub(src_off);
                    let copy_len = avail.min(len);
                    let mut buf = vec![0u8; len];
                    if copy_len > 0 {
                        buf[..copy_len].copy_from_slice(&rd[src_off..src_off + copy_len]);
                    }
                    self.memory.store(dest, &buf)?;
                }
                0x3f => {
                    let addr = u256_to_pqaddress(self.pop()?);
                    let hash = db_err!(db.account(addr))?.map_or(B256::ZERO, |a| a.code_hash);
                    self.push(U256::from_be_bytes(hash.0))?;
                }

                // ── Block information ─────────────────────────────────────
                0x40 => {
                    let n = self.pop()?.to::<u64>();
                    let h = db_err!(db.block_hash(n))?;
                    self.push(U256::from_be_bytes(h.0))?;
                }
                0x41 => self.push(pqaddress_to_u256(env.coinbase))?,
                0x42 => self.push(U256::from(env.timestamp))?,
                0x43 => self.push(U256::from(env.block_number))?,
                0x44 => self.push(U256::ZERO)?, // PREVRANDAO: not applicable to PQVM
                0x45 => self.push(U256::from(env.gas_limit))?,
                0x46 => self.push(U256::from(env.chain_id))?,
                0x47 => {
                    let bal = db_err!(db.account(ctx.address))?.map_or(U256::ZERO, |a| a.balance);
                    self.push(bal)?;
                }
                0x48 => self.push(U256::ZERO)?, // BASEFEE: 0 (no EIP-1559 in PQVM-1)

                // ── Stack / Memory ────────────────────────────────────────
                0x50 => {
                    self.pop()?;
                }
                0x51 => {
                    let offset = u256_to_usize(self.pop()?)?;
                    let mem_gas = self.memory.resize_for_access(offset, 32)?;
                    gas.charge(mem_gas)?;
                    let word = self.memory.load(offset, 32)?;
                    let mut bytes = [0u8; 32];
                    bytes.copy_from_slice(word);
                    self.push(U256::from_be_bytes(bytes))?;
                }
                0x52 => {
                    let offset = u256_to_usize(self.pop()?)?;
                    let value = self.pop()?;
                    let bytes = value.to_be_bytes::<32>();
                    let mem_gas = self.memory.store(offset, &bytes)?;
                    gas.charge(mem_gas)?;
                }
                0x53 => {
                    let offset = u256_to_usize(self.pop()?)?;
                    let value = self.pop()?;
                    let byte = value.to_be_bytes::<32>()[31];
                    let mem_gas = self.memory.store(offset, &[byte])?;
                    gas.charge(mem_gas)?;
                }

                // ── Storage ───────────────────────────────────────────────
                0x54 => {
                    let key = self.pop()?;
                    let val = db_err!(db.storage(ctx.address, key))?;
                    self.push(val)?;
                }
                0x55 => {
                    if ctx.is_static {
                        return Err(InterpreterError::StaticViolation);
                    }
                    let key = self.pop()?;
                    let new_val = self.pop()?;
                    let old_val = db_err!(db.storage(ctx.address, key))?;
                    let sstore_cost = if old_val == new_val {
                        GAS_SSTORE_NOOP
                    } else if old_val.is_zero() {
                        gas.charge(GAS_SSTORE_SET - GAS_SSTORE_RESET)?;
                        GAS_SSTORE_RESET
                    } else {
                        0
                    };
                    gas.charge(sstore_cost)?;
                    db_err!(db.write_storage(ctx.address, key, new_val))?;
                }

                // ── Control flow ──────────────────────────────────────────
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
                0x5a => self.push(U256::from(gas.remaining()))?,
                0x5b => {} // JUMPDEST: no-op
                0x5c => {
                    // TLOAD: transient storage — treat as zero (no persistence)
                    let _key = self.pop()?;
                    self.push(U256::ZERO)?;
                }
                0x5d => {
                    // TSTORE: transient storage — accept and discard
                    self.pop()?;
                    self.pop()?;
                }
                0x5f => self.push(U256::ZERO)?,

                // ── PUSH1..PUSH32 ─────────────────────────────────────────
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

                // ── DUP1..DUP16 ──────────────────────────────────────────
                0x80..=0x8f => {
                    let depth = (opcode - 0x7f) as usize;
                    let value = self.peek(depth)?;
                    self.push(value)?;
                }

                // ── SWAP1..SWAP16 ─────────────────────────────────────────
                0x90..=0x9f => {
                    let depth = (opcode - 0x8f) as usize;
                    self.swap(depth)?;
                }

                // ── LOG0..LOG4 ────────────────────────────────────────────
                0xa0..=0xa4 => {
                    if ctx.is_static {
                        return Err(InterpreterError::StaticViolation);
                    }
                    let topic_count = (opcode - 0xa0) as usize;
                    let offset = u256_to_usize(self.pop()?)?;
                    let len = u256_to_usize(self.pop()?)?;
                    let mem_gas = self.memory.resize_for_access(offset, len)?;
                    gas.charge(mem_gas)?;
                    gas.charge(len as u64 * GAS_LOG_PER_BYTE)?;
                    let data = Bytes::copy_from_slice(self.memory.load(offset, len)?);
                    let mut topics = Vec::with_capacity(topic_count);
                    for _ in 0..topic_count {
                        let t = self.pop()?;
                        topics.push(B256::from(t.to_be_bytes::<32>()));
                    }
                    logs.push(LogEntry {
                        address: ctx.address,
                        topics,
                        data,
                    });
                }

                // ── PQ native opcodes ─────────────────────────────────────
                PQVERIFY_OPCODE => {
                    let algo_id = self.pop()?.to::<u8>();
                    let offset = u256_to_usize(self.pop()?)?;
                    let len = u256_to_usize(self.pop()?)?;
                    let mem_gas = self.memory.resize_for_access(offset, len)?;
                    gas.charge(mem_gas)?;
                    let input = self.memory.load(offset, len)?.to_vec();
                    let precompile = match algo_id {
                        0x01 => Some(ML_DSA_65_VERIFY),
                        0x02 => Some(SLH_DSA_SHA2_256F_VERIFY),
                        _ => None,
                    };
                    let valid = if let Some(address) = precompile {
                        let output = BasicPqPrecompiles
                            .execute(address, &input, gas.remaining())
                            .map_err(|err| InterpreterError::Precompile(err.to_string()))?
                            .ok_or_else(|| {
                                InterpreterError::Precompile("missing PQVERIFY precompile".into())
                            })?;
                        gas.charge(output.gas_used)?;
                        output.output.first().copied().unwrap_or_default()
                    } else {
                        0
                    };
                    self.push(U256::from(valid))?;
                }
                PQHASH_OPCODE => {
                    let dest = u256_to_usize(self.pop()?)?;
                    let offset = u256_to_usize(self.pop()?)?;
                    let len = u256_to_usize(self.pop()?)?;
                    let mem_gas = self.memory.resize_for_access(offset, len)?;
                    gas.charge(mem_gas)?;
                    let input = self.memory.load(offset, len)?.to_vec();
                    let output = BasicPqPrecompiles
                        .execute(BLAKE3_256, &input, gas.remaining())
                        .map_err(|err| InterpreterError::Precompile(err.to_string()))?
                        .ok_or_else(|| {
                            InterpreterError::Precompile("missing PQHASH precompile".into())
                        })?;
                    gas.charge(output.gas_used)?;
                    let mem_gas = self.memory.store(dest, &output.output)?;
                    gas.charge(mem_gas)?;
                }
                PQADDR_OPCODE => {
                    let dest = u256_to_usize(self.pop()?)?;
                    let offset = u256_to_usize(self.pop()?)?;
                    let len = u256_to_usize(self.pop()?)?;
                    let mem_gas = self.memory.resize_for_access(offset, len)?;
                    gas.charge(mem_gas)?;
                    let input = self.memory.load(offset, len)?.to_vec();
                    let output = BasicPqPrecompiles
                        .execute(PQADDRESS_DERIVE, &input, gas.remaining())
                        .map_err(|err| InterpreterError::Precompile(err.to_string()))?
                        .ok_or_else(|| {
                            InterpreterError::Precompile("missing PQADDR precompile".into())
                        })?;
                    gas.charge(output.gas_used)?;
                    let mem_gas = self.memory.store(dest, &output.output)?;
                    gas.charge(mem_gas)?;
                }

                // ── CALL / DELEGATECALL / STATICCALL ─────────────────────
                0xf1 | 0xf4 | 0xfa => {
                    let is_static_call = opcode == 0xfa;
                    let is_delegate = opcode == 0xf4;

                    if ctx.is_static && !is_static_call {
                        return Err(InterpreterError::StaticViolation);
                    }

                    let gas_stack = self.pop()?.saturating_to::<u64>();
                    let callee_addr = u256_to_pqaddress(self.pop()?);
                    let value = if is_delegate || is_static_call {
                        U256::ZERO
                    } else {
                        self.pop()?
                    };
                    let args_offset = u256_to_usize(self.pop()?)?;
                    let args_len = u256_to_usize(self.pop()?)?;
                    let ret_offset = u256_to_usize(self.pop()?)?;
                    let ret_len = u256_to_usize(self.pop()?)?;

                    // Read calldata from memory.
                    let mem_gas = self.memory.resize_for_access(args_offset, args_len)?;
                    gas.charge(mem_gas)?;
                    let calldata = Bytes::copy_from_slice(self.memory.load(args_offset, args_len)?);

                    // Value-transfer costs.
                    if !value.is_zero() {
                        gas.charge(GAS_CALL_VALUE)?;
                        let to_exists = db_err!(db.account(callee_addr))?.is_some();
                        if !to_exists {
                            gas.charge(GAS_CALL_NEW_ACCOUNT)?;
                        }
                    }

                    // Determine how much gas to pass (EIP-150: 63/64 rule).
                    let forwarded = gas.remaining().saturating_sub(gas.remaining() / 64);
                    let stipend = if !value.is_zero() {
                        GAS_CALL_STIPEND
                    } else {
                        0
                    };
                    let sub_gas = forwarded.min(gas_stack).saturating_add(stipend);

                    if ctx.depth >= MAX_CALL_DEPTH {
                        self.returndata = Bytes::new();
                        self.push(U256::ZERO)?;
                        continue;
                    }

                    // Load callee code.
                    let callee_code = db_err!(db.account(callee_addr))?
                        .map(|a| a.code.to_vec())
                        .unwrap_or_default();

                    let sub_ctx = FrameContext {
                        code: callee_code,
                        calldata,
                        caller: if is_delegate { ctx.caller } else { ctx.address },
                        address: if is_delegate {
                            ctx.address
                        } else {
                            callee_addr
                        },
                        value: if is_delegate { ctx.value } else { value },
                        origin: ctx.origin,
                        is_static: ctx.is_static || is_static_call,
                        depth: ctx.depth + 1,
                        gas_limit: sub_gas,
                    };

                    let checkpoint = db.state_checkpoint();

                    // Transfer value before executing (non-delegate only).
                    if !value.is_zero() && !is_delegate {
                        if let Err(e) = db.move_value(ctx.address, callee_addr, value) {
                            let _ = db.state_revert(checkpoint);
                            self.returndata = Bytes::new();
                            self.push(U256::ZERO)?;
                            gas.charge(0)
                                .map_err(|_| InterpreterError::Database(e.to_string()))?;
                            continue;
                        }
                    }

                    let mut sub_interp = Interpreter::default();
                    let sub_result = sub_interp.execute_frame(db, env, &sub_ctx);

                    let (success, sub_out, sub_logs, sub_gas_used) = match sub_result {
                        Ok(r) => {
                            let ok = r.status == ExecutionStatus::Success;
                            (ok, r.output, r.logs, r.gas_used)
                        }
                        Err(_) => (false, Bytes::new(), vec![], sub_gas),
                    };

                    if success {
                        db_err!(db.state_commit(checkpoint))?;
                        logs.extend(sub_logs);
                    } else {
                        db_err!(db.state_revert(checkpoint))?;
                    }

                    // Charge gas used by sub-call (minus stipend).
                    let net_gas_used = sub_gas_used.saturating_sub(stipend);
                    gas.charge(net_gas_used.min(gas.remaining()))?;

                    // Write return data to memory.
                    self.returndata = sub_out.clone();
                    let copy_len = sub_out.len().min(ret_len);
                    if copy_len > 0 {
                        let mem_gas = self.memory.resize_for_access(ret_offset, copy_len)?;
                        gas.charge(mem_gas)?;
                        self.memory.store(ret_offset, &sub_out[..copy_len])?;
                    }

                    self.push(U256::from(success as u64))?;
                }

                // ── CREATE ────────────────────────────────────────────────
                0xf0 => {
                    if ctx.is_static {
                        return Err(InterpreterError::StaticViolation);
                    }
                    if ctx.depth >= MAX_CALL_DEPTH {
                        self.push(U256::ZERO)?;
                        continue;
                    }

                    let value = self.pop()?;
                    let offset = u256_to_usize(self.pop()?)?;
                    let len = u256_to_usize(self.pop()?)?;
                    let mem_gas = self.memory.resize_for_access(offset, len)?;
                    gas.charge(mem_gas)?;
                    let byte_cost = len as u64 * GAS_CREATE_PER_BYTE;
                    gas.charge(byte_cost)?;
                    let initcode = self.memory.load(offset, len)?.to_vec();

                    // Derive new contract address: BLAKE3(0x00 || sender || nonce).
                    let nonce = db_err!(db.account(ctx.address))?.map_or(0u64, |a| a.nonce);
                    let new_addr = create_address(ctx.address, nonce);

                    let checkpoint = db.state_checkpoint();
                    if !value.is_zero() {
                        if let Err(e) = db.move_value(ctx.address, new_addr, value) {
                            let _ = db.state_revert(checkpoint);
                            self.push(U256::ZERO)?;
                            let _ = InterpreterError::Database(e.to_string());
                            continue;
                        }
                    }

                    let forwarded = gas.remaining().saturating_sub(gas.remaining() / 64);
                    let sub_ctx = FrameContext {
                        code: initcode,
                        calldata: Bytes::new(),
                        caller: ctx.address,
                        address: new_addr,
                        value,
                        origin: ctx.origin,
                        is_static: false,
                        depth: ctx.depth + 1,
                        gas_limit: forwarded,
                    };

                    let mut sub_interp = Interpreter::default();
                    let sub_result = sub_interp.execute_frame(db, env, &sub_ctx);

                    match sub_result {
                        Ok(r) if r.status == ExecutionStatus::Success => {
                            let runtime_code = r.output.to_vec();
                            let code_hash = {
                                let h = keccak256(&runtime_code);
                                B256::from(h.0)
                            };
                            let acct = db_err!(db.account(new_addr))?.unwrap_or_default();
                            db_err!(db.write_account(
                                new_addr,
                                AccountInfo {
                                    code: Bytes::from(runtime_code),
                                    code_hash,
                                    ..acct
                                },
                            ))?;
                            db_err!(db.state_commit(checkpoint))?;
                            logs.extend(r.logs);
                            self.push(pqaddress_to_u256(new_addr))?;
                        }
                        _ => {
                            db_err!(db.state_revert(checkpoint))?;
                            self.push(U256::ZERO)?;
                        }
                    }
                }

                // ── CREATE2 ───────────────────────────────────────────────
                0xf5 => {
                    if ctx.is_static {
                        return Err(InterpreterError::StaticViolation);
                    }
                    if ctx.depth >= MAX_CALL_DEPTH {
                        self.push(U256::ZERO)?;
                        continue;
                    }

                    let value = self.pop()?;
                    let offset = u256_to_usize(self.pop()?)?;
                    let len = u256_to_usize(self.pop()?)?;
                    let salt = self.pop()?;
                    let mem_gas = self.memory.resize_for_access(offset, len)?;
                    gas.charge(mem_gas)?;
                    let per_word = words_for_len(len)? as u64 * GAS_CREATE2_EXTRA_PER_WORD;
                    gas.charge(len as u64 * GAS_CREATE_PER_BYTE + per_word)?;
                    let initcode = self.memory.load(offset, len)?.to_vec();

                    let new_addr = create2_address(ctx.address, salt, &initcode);

                    let checkpoint = db.state_checkpoint();
                    if !value.is_zero() {
                        if let Err(e) = db.move_value(ctx.address, new_addr, value) {
                            let _ = db.state_revert(checkpoint);
                            self.push(U256::ZERO)?;
                            let _ = InterpreterError::Database(e.to_string());
                            continue;
                        }
                    }

                    let forwarded = gas.remaining().saturating_sub(gas.remaining() / 64);
                    let sub_ctx = FrameContext {
                        code: initcode,
                        calldata: Bytes::new(),
                        caller: ctx.address,
                        address: new_addr,
                        value,
                        origin: ctx.origin,
                        is_static: false,
                        depth: ctx.depth + 1,
                        gas_limit: forwarded,
                    };

                    let mut sub_interp = Interpreter::default();
                    let sub_result = sub_interp.execute_frame(db, env, &sub_ctx);

                    match sub_result {
                        Ok(r) if r.status == ExecutionStatus::Success => {
                            let runtime_code = r.output.to_vec();
                            let code_hash = {
                                let h = keccak256(&runtime_code);
                                B256::from(h.0)
                            };
                            let acct = db_err!(db.account(new_addr))?.unwrap_or_default();
                            db_err!(db.write_account(
                                new_addr,
                                AccountInfo {
                                    code: Bytes::from(runtime_code),
                                    code_hash,
                                    ..acct
                                },
                            ))?;
                            db_err!(db.state_commit(checkpoint))?;
                            logs.extend(r.logs);
                            self.push(pqaddress_to_u256(new_addr))?;
                        }
                        _ => {
                            db_err!(db.state_revert(checkpoint))?;
                            self.push(U256::ZERO)?;
                        }
                    }
                }

                // ── RETURN ────────────────────────────────────────────────
                0xf3 => {
                    let offset = u256_to_usize(self.pop()?)?;
                    let len = u256_to_usize(self.pop()?)?;
                    let mem_gas = self.memory.resize_for_access(offset, len)?;
                    gas.charge(mem_gas)?;
                    let output = Bytes::copy_from_slice(self.memory.load(offset, len)?);
                    return Ok(ExecutionResult {
                        status: ExecutionStatus::Success,
                        gas_used: gas.used(),
                        output,
                        logs,
                    });
                }

                // ── REVERT ────────────────────────────────────────────────
                0xfd => {
                    let offset = u256_to_usize(self.pop()?)?;
                    let len = u256_to_usize(self.pop()?)?;
                    let mem_gas = self.memory.resize_for_access(offset, len)?;
                    gas.charge(mem_gas)?;
                    let output = Bytes::copy_from_slice(self.memory.load(offset, len)?);
                    return Ok(ExecutionResult {
                        status: ExecutionStatus::Revert,
                        gas_used: gas.used(),
                        output,
                        logs: vec![], // logs discarded on REVERT
                    });
                }

                // ── SELFDESTRUCT ──────────────────────────────────────────
                0xff => {
                    if ctx.is_static {
                        return Err(InterpreterError::StaticViolation);
                    }
                    let target = u256_to_pqaddress(self.pop()?);
                    let balance =
                        db_err!(db.account(ctx.address))?.map_or(U256::ZERO, |a| a.balance);
                    if !balance.is_zero() {
                        db_err!(db.move_value(ctx.address, target, balance))?;
                    }
                    db_err!(db.erase_account(ctx.address))?;
                    return Ok(ExecutionResult {
                        status: ExecutionStatus::Success,
                        gas_used: gas.used(),
                        output: Bytes::new(),
                        logs,
                    });
                }

                // ── Removed / forbidden opcodes ───────────────────────────
                0xf2 => return Err(InterpreterError::RemovedOpcode("CALLCODE")),

                other => return Err(InterpreterError::UnsupportedOpcode(other)),
            }
        }

        Ok(ExecutionResult {
            status: ExecutionStatus::Success,
            gas_used: gas.used(),
            output: Bytes::new(),
            logs,
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

// ── Contract address derivation ───────────────────────────────────────────────

/// `CREATE` address: `BLAKE3(0x00 || sender || nonce_be8)[0:32]`
fn create_address(sender: PQAddress, nonce: u64) -> PQAddress {
    let mut h = blake3::Hasher::new();
    h.update(&[0x00]);
    h.update(sender.as_bytes());
    h.update(&nonce.to_be_bytes());
    PQAddress(*h.finalize().as_bytes())
}

/// `CREATE2` address: `BLAKE3(0xff || sender || salt || BLAKE3(initcode))[0:32]`
fn create2_address(sender: PQAddress, salt: U256, initcode: &[u8]) -> PQAddress {
    let mut init_hash = blake3::Hasher::new();
    init_hash.update(initcode);
    let code_hash = init_hash.finalize();

    let mut h = blake3::Hasher::new();
    h.update(&[0xff]);
    h.update(sender.as_bytes());
    h.update(&salt.to_be_bytes::<32>());
    h.update(code_hash.as_bytes());
    PQAddress(*h.finalize().as_bytes())
}

// ── Address conversion helpers ────────────────────────────────────────────────

fn pqaddress_to_u256(addr: PQAddress) -> U256 {
    U256::from_be_bytes(addr.0)
}

fn u256_to_pqaddress(v: U256) -> PQAddress {
    PQAddress(v.to_be_bytes::<32>())
}

// ── Jump / code analysis ──────────────────────────────────────────────────────

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

// ── Arithmetic helpers ────────────────────────────────────────────────────────

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

/// Arithmetic shift right — uses I256 for correct two's-complement semantics.
fn sar(shift: U256, value: U256) -> U256 {
    if shift >= U256::from(256) {
        // All bits become the sign bit.
        if value.bit(255) {
            U256::MAX
        } else {
            U256::ZERO
        }
    } else {
        let shift = shift.to::<usize>();
        I256::from_raw(value).asr(shift).into_raw()
    }
}

fn u256_to_usize(value: U256) -> Result<usize, InterpreterError> {
    if value > U256::from(usize::MAX) {
        return Err(InterpreterError::MemoryOverflow);
    }
    Ok(value.to::<usize>())
}

// ── Test helpers ──────────────────────────────────────────────────────────────

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

    fn write_account(
        &mut self,
        _address: PQAddress,
        _account: AccountInfo,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn write_storage(
        &mut self,
        _address: PQAddress,
        _index: U256,
        _value: U256,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn erase_account(&mut self, _address: PQAddress) -> Result<(), Self::Error> {
        Ok(())
    }

    fn move_value(
        &mut self,
        _from: PQAddress,
        _to: PQAddress,
        _value: U256,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    fn state_checkpoint(&mut self) -> usize {
        0
    }

    fn state_revert(&mut self, _checkpoint: usize) -> Result<(), Self::Error> {
        Ok(())
    }

    fn state_commit(&mut self, _checkpoint: usize) -> Result<(), Self::Error> {
        Ok(())
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Bytes;
    use pqcrypto_dilithium::dilithium3;
    use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

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
    fn keccak256_opcode_hashes_memory() {
        let mut db = EmptyDb;
        let mut interpreter = Interpreter::default();
        interpreter.memory.store(0, b"abc").unwrap();
        interpreter
            .execute(
                &mut db,
                &env(),
                &tx(&[
                    0x60, 0x03, // len 3
                    0x60, 0x00, // offset 0
                    0x20, // KECCAK256
                    0x00,
                ]),
            )
            .unwrap();
        let result = interpreter.pop().unwrap();
        let expected = keccak256(b"abc");
        assert_eq!(result, U256::from_be_bytes(expected.0));
    }

    #[test]
    fn context_opcodes_return_frame_values() {
        let mut db = EmptyDb;
        let mut interpreter = Interpreter::default();
        // Use execute_frame with an explicit context.
        let ctx = FrameContext {
            code: vec![0x33, 0x34, 0x36, 0x00], // CALLER CALLVALUE CALLDATASIZE STOP
            calldata: Bytes::from_static(b"hello"),
            caller: PQAddress([0xca; 32]),
            address: PQAddress([0xad; 32]),
            value: U256::from(42u64),
            origin: PQAddress::zero(),
            is_static: false,
            depth: 0,
            gas_limit: 1_000_000,
        };
        interpreter.execute_frame(&mut db, &env(), &ctx).unwrap();
        assert_eq!(interpreter.pop().unwrap(), U256::from(5u64)); // calldatasize
        assert_eq!(interpreter.pop().unwrap(), U256::from(42u64)); // callvalue
        assert_eq!(
            interpreter.pop().unwrap(),
            pqaddress_to_u256(PQAddress([0xca; 32]))
        ); // caller
    }

    #[test]
    fn sstore_and_sload_round_trip() {
        use pqvm_state::PqvmState;
        let mut state = PqvmState::default();
        let addr = PQAddress([0x11; 32]);
        state.insert_account(addr, pqvm_state::AccountInfo::default());
        let mut interpreter = Interpreter::default();
        let ctx = FrameContext {
            code: vec![
                0x60, 0x2a, // PUSH1 42 (value)
                0x60, 0x01, // PUSH1 key=1
                0x55, // SSTORE
                0x60, 0x01, // PUSH1 key=1
                0x54, // SLOAD
                0x00,
            ],
            calldata: Bytes::new(),
            caller: PQAddress::zero(),
            address: addr,
            value: U256::ZERO,
            origin: PQAddress::zero(),
            is_static: false,
            depth: 0,
            gas_limit: 5_000_000,
        };
        interpreter.execute_frame(&mut state, &env(), &ctx).unwrap();
        assert_eq!(interpreter.pop().unwrap(), U256::from(42u64));
    }

    #[test]
    fn log1_is_emitted_with_topic_and_data() {
        let mut db = EmptyDb;
        let mut interpreter = Interpreter::default();
        interpreter.memory.store(0, &[0xab, 0xcd]).unwrap();
        let ctx = FrameContext {
            code: vec![
                0x60, 0xbb, // topic
                0x60, 0x02, // len 2
                0x60, 0x00, // offset 0
                0xa1, // LOG1
                0x00,
            ],
            calldata: Bytes::new(),
            caller: PQAddress::zero(),
            address: PQAddress([0x11; 32]),
            value: U256::ZERO,
            origin: PQAddress::zero(),
            is_static: false,
            depth: 0,
            gas_limit: 1_000_000,
        };
        let result = interpreter.execute_frame(&mut db, &env(), &ctx).unwrap();
        assert_eq!(result.logs.len(), 1);
        assert_eq!(result.logs[0].data.as_ref(), &[0xab, 0xcd]);
        assert_eq!(result.logs[0].topics.len(), 1);
    }

    #[test]
    fn call_transfers_value_and_returns_success() {
        use pqvm_state::{AccountInfo, PqvmState};
        let mut state = PqvmState::default();
        let caller_addr = PQAddress([0x11; 32]);
        let callee_addr = PQAddress([0x22; 32]);
        state.insert_account(
            caller_addr,
            AccountInfo {
                balance: U256::from(1000u64),
                ..Default::default()
            },
        );
        // callee has code: STOP
        state.insert_account(
            callee_addr,
            AccountInfo {
                code: Bytes::from_static(&[0x00]),
                ..Default::default()
            },
        );

        let ctx = FrameContext {
            code: vec![
                // CALL(gas=50000, addr=callee, value=100, argsOff=0, argsLen=0, retOff=0, retLen=0)
                0x60, 0x00, // retLen
                0x60, 0x00, // retOff
                0x60, 0x00, // argsLen
                0x60, 0x00, // argsOff
                0x60, 0x64, // value 100
                // push callee address (32 bytes via PUSH32)
                0x7f, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
                0x22, 0x22, 0x22, 0x22, 0x22, 0x62, 0x00, 0xc3, 0x50, // gas 50000
                0xf1, // CALL
                0x00,
            ],
            calldata: Bytes::new(),
            caller: PQAddress::zero(),
            address: caller_addr,
            value: U256::ZERO,
            origin: PQAddress::zero(),
            is_static: false,
            depth: 0,
            gas_limit: 5_000_000,
        };
        let mut interpreter = Interpreter::default();
        interpreter.execute_frame(&mut state, &env(), &ctx).unwrap();
        // CALL result on stack: 1 = success
        assert_eq!(interpreter.pop().unwrap(), U256::from(1u64));
        // callee received 100
        assert_eq!(
            state.account_ref(callee_addr).unwrap().balance,
            U256::from(100u64)
        );
    }

    #[test]
    fn create_deploys_contract_and_returns_address() {
        use pqvm_state::{AccountInfo, PqvmState};
        let mut state = PqvmState::default();
        let creator = PQAddress([0x11; 32]);
        state.insert_account(
            creator,
            AccountInfo {
                nonce: 0,
                balance: U256::ZERO,
                ..Default::default()
            },
        );

        // initcode: PUSH1 0x60; PUSH1 0x00; RETURN (returns 1 byte as runtime code)
        let initcode: Vec<u8> = vec![0x60, 0x60, 0x60, 0x00, 0xf3];
        let init_len = initcode.len() as u8;

        let code = vec![
            // store initcode at memory[0]
            // MSTORE8 each byte manually is tedious; use memory pre-load trick
            // Instead, place initcode in calldata and use CALLDATACOPY
            0x60, init_len, // len
            0x60, 0x00, // src offset
            0x60, 0x00, // dst offset
            0x37, // CALLDATACOPY
            // CREATE(value=0, offset=0, len=init_len)
            0x60, init_len, // len
            0x60, 0x00, // offset
            0x60, 0x00, // value
            0xf0, // CREATE
            0x00,
        ];
        let _ = code; // suppress warning

        let ctx = FrameContext {
            code: vec![
                0x60, init_len, 0x60, 0x00, 0x60, 0x00, 0x37, // CALLDATACOPY
                0x60, init_len, 0x60, 0x00, 0x60, 0x00, 0xf0, // CREATE
                0x00,
            ],
            calldata: Bytes::from(initcode),
            caller: PQAddress::zero(),
            address: creator,
            value: U256::ZERO,
            origin: PQAddress::zero(),
            is_static: false,
            depth: 0,
            gas_limit: 5_000_000,
        };
        let mut interpreter = Interpreter::default();
        interpreter.execute_frame(&mut state, &env(), &ctx).unwrap();
        let new_addr_u256 = interpreter.pop().unwrap();
        // Non-zero means success
        assert_ne!(new_addr_u256, U256::ZERO);
        let new_addr = u256_to_pqaddress(new_addr_u256);
        // New account should have been created
        assert!(state.account_ref(new_addr).is_some());
    }

    #[test]
    fn pqhash_opcode_writes_blake3_256_to_memory() {
        let mut db = EmptyDb;
        let mut interpreter = Interpreter::default();
        interpreter.memory.store(0, b"abc").unwrap();
        interpreter
            .execute(
                &mut db,
                &env(),
                &tx(&[
                    0x60,
                    0x03, // len
                    0x60,
                    0x00, // offset
                    0x60,
                    0x20, // destination
                    PQHASH_OPCODE,
                    0x00,
                ]),
            )
            .unwrap();

        assert_eq!(
            &interpreter.memory.as_slice()[32..64],
            blake3::hash(b"abc").as_bytes()
        );
    }

    #[test]
    fn pqaddr_opcode_writes_derived_address_to_memory() {
        let mut db = EmptyDb;
        let mut interpreter = Interpreter::default();
        let mut input = vec![0x01];
        input.extend_from_slice(b"public-key");
        interpreter.memory.store(0, &input).unwrap();
        interpreter
            .execute(
                &mut db,
                &env(),
                &tx(&[
                    0x60,
                    input.len() as u8, // len
                    0x60,
                    0x00, // offset
                    0x60,
                    0x40, // destination
                    PQADDR_OPCODE,
                    0x00,
                ]),
            )
            .unwrap();

        assert_eq!(
            &interpreter.memory.as_slice()[64..96],
            PQAddress::derive(0x01, b"public-key").as_bytes()
        );
    }

    #[test]
    fn pqverify_opcode_pushes_one_for_valid_ml_dsa_signature() {
        let mut db = EmptyDb;
        let mut interpreter = Interpreter::default();
        let (pk, sk) = dilithium3::keypair();
        let message = b"pqverify opcode";
        let sig = dilithium3::detached_sign(message, &sk);
        let mut input = Vec::new();
        input.extend_from_slice(pk.as_bytes());
        input.extend_from_slice(sig.as_bytes());
        input.extend_from_slice(message);
        interpreter.memory.store(0, &input).unwrap();
        interpreter
            .execute(
                &mut db,
                &env(),
                &tx(&[
                    0x61,
                    ((input.len() >> 8) & 0xff) as u8,
                    (input.len() & 0xff) as u8, // len
                    0x60,
                    0x00, // offset
                    0x60,
                    0x01, // algo id
                    PQVERIFY_OPCODE,
                    0x00,
                ]),
            )
            .unwrap();

        assert_eq!(interpreter.pop().unwrap(), U256::from(1));
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
        assert_eq!(opcode_info(0xf1).unwrap().name, "CALL");
        assert_eq!(opcode_info(0xff).unwrap().name, "SELFDESTRUCT");
        assert!(opcode_info(0xfe).is_none());
    }

    /// Tests for SDIV/SMOD/SLT/SGT/SAR using full 256-bit I256.
    /// Validates that large signed values (>128 bit) work correctly.
    #[test]
    fn signed_arithmetic_uses_full_i256() {
        let mut db = EmptyDb;
        let env = env();

        // SDIV: (-1) / 2 = 0 (truncated toward zero)
        // binary_op pops `a` first (top/divisor), `b` second (dividend).
        // So push dividend first then divisor on top.
        let neg1 = U256::MAX; // two's-complement -1
        let mut code = vec![0x7fu8]; // PUSH32 neg1 (dividend, will be `b`)
        code.extend_from_slice(&neg1.to_be_bytes::<32>());
        code.push(0x60); // PUSH1 2 (divisor, will be `a` = top of stack)
        code.push(0x02);
        code.push(0x05); // SDIV  → result = b/a = (-1)/2 = 0
        code.push(0x00); // STOP
        let ctx = FrameContext {
            code: code.clone(),
            calldata: Bytes::new(),
            caller: PQAddress::zero(),
            address: PQAddress::zero(),
            value: U256::ZERO,
            origin: PQAddress::zero(),
            is_static: false,
            depth: 0,
            gas_limit: 1_000_000,
        };
        let mut interp = Interpreter::default();
        interp.execute_frame(&mut db, &env, &ctx).unwrap();
        // -1 / 2 = 0 (truncated toward zero in EVM signed div)
        assert_eq!(interp.pop().unwrap(), U256::ZERO);

        // SLT: large negative < large positive → 1
        // Push I256::MIN (most negative) and I256::MAX (most positive), then SLT
        let i256_min: U256 = U256::from(1u8) << 255; // bit255 set, rest zero = I256::MIN
        let i256_max: U256 = (U256::from(1u8) << 255) - U256::from(1u8); // 0x7fff...fff = I256::MAX
                                                                         // SLT pushes `b` first (dividend/second), `a` on top (first popped).
                                                                         // Result: b < a. We want i256_min < i256_max → push i256_min first, then i256_max on top.
        let mut code2 = vec![0x7fu8]; // PUSH32 i256_min (will be `b`)
        code2.extend_from_slice(&i256_min.to_be_bytes::<32>());
        code2.push(0x7f); // PUSH32 i256_max (will be `a` = top)
        code2.extend_from_slice(&i256_max.to_be_bytes::<32>());
        code2.push(0x12); // SLT: b < a → i256_min < i256_max → true
        code2.push(0x00);
        let ctx2 = FrameContext {
            code: code2,
            ..ctx.clone()
        };
        let mut interp2 = Interpreter::default();
        interp2.execute_frame(&mut db, &env, &ctx2).unwrap();
        assert_eq!(interp2.pop().unwrap(), U256::from(1u8)); // -MIN < MAX → true

        // SAR: arithmetic right-shift of -1 by 1 = -1 (fills with sign bit)
        let mut code3 = vec![0x7fu8]; // PUSH32 -1
        code3.extend_from_slice(&U256::MAX.to_be_bytes::<32>());
        code3.push(0x60); // PUSH1 1
        code3.push(0x01);
        code3.push(0x1d); // SAR
        code3.push(0x00);
        let ctx3 = FrameContext { code: code3, ..ctx };
        let mut interp3 = Interpreter::default();
        interp3.execute_frame(&mut db, &env, &ctx3).unwrap();
        assert_eq!(interp3.pop().unwrap(), U256::MAX); // SAR(-1, 1) = -1
    }
}
