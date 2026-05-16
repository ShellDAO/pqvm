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
