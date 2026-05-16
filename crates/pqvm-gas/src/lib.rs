//! PQVM gas constants and helpers.

pub const BLOCK_GAS_LIMIT: u64 = 50_000_000;
pub const MAX_TX_PER_BLOCK: usize = 500;

pub const INTRINSIC_GAS_TX: u64 = 21_000;
pub const ML_DSA_65_VERIFY_GAS: u64 = 46_000;
pub const SLH_DSA_SHA2_256F_VERIFY_GAS: u64 = 2_300_000;
pub const ML_DSA_65_BATCH_VERIFY_GAS_PER_SIG: u64 = 12_000;
pub const BLAKE3_BASE_GAS: u64 = 30;
pub const BLAKE3_WORD_GAS: u64 = 6;
pub const PQADDRESS_DERIVE_GAS: u64 = 200;

pub const PQVERIFY_OPCODE: u8 = 0xB0;
pub const PQHASH_OPCODE: u8 = 0xB1;
pub const PQADDR_OPCODE: u8 = 0xB2;

// ── EVM-compatible opcode gas ─────────────────────────────────────────────

pub const GAS_VERYLOW: u64 = 1;
pub const GAS_LOW: u64 = 2;
pub const GAS_KECCAK256_BASE: u64 = 30;
pub const GAS_KECCAK256_PER_WORD: u64 = 6;
pub const GAS_COPY_PER_WORD: u64 = 3;
pub const GAS_BALANCE: u64 = 700;
pub const GAS_EXTCODE: u64 = 700;
pub const GAS_BLOCKHASH: u64 = 20;
pub const GAS_SELFBALANCE: u64 = 5;
pub const GAS_CHAINID: u64 = 2;
pub const GAS_BASEFEE: u64 = 2;
pub const GAS_SLOAD: u64 = 800;
pub const GAS_SSTORE_SET: u64 = 20_000;
pub const GAS_SSTORE_RESET: u64 = 2_900;
pub const GAS_SSTORE_NOOP: u64 = 100;
pub const GAS_LOG_BASE: u64 = 375;
pub const GAS_LOG_PER_TOPIC: u64 = 375;
pub const GAS_LOG_PER_BYTE: u64 = 8;
pub const GAS_CALL_BASE: u64 = 700;
pub const GAS_CALL_VALUE: u64 = 9_000;
pub const GAS_CALL_NEW_ACCOUNT: u64 = 25_000;
pub const GAS_CALL_STIPEND: u64 = 2_300;
pub const GAS_CREATE_BASE: u64 = 32_000;
pub const GAS_CREATE_PER_BYTE: u64 = 200;
pub const GAS_CREATE2_EXTRA_PER_WORD: u64 = 6;
pub const GAS_SELFDESTRUCT: u64 = 5_000;

/// Maximum nested call depth, matching EIP-150.
pub const MAX_CALL_DEPTH: usize = 1024;

pub fn simple_ml_dsa_transfer_gas() -> u64 {
    INTRINSIC_GAS_TX + ML_DSA_65_VERIFY_GAS
}

pub fn simple_ml_dsa_transfers_by_gas() -> u64 {
    BLOCK_GAS_LIMIT / simple_ml_dsa_transfer_gas()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hard_cap_binds_for_simple_ml_dsa_transfers() {
        assert_eq!(500 * simple_ml_dsa_transfer_gas(), 33_500_000);
        assert!(simple_ml_dsa_transfers_by_gas() > MAX_TX_PER_BLOCK as u64);
    }
}
