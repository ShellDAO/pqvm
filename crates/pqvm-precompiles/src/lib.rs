//! PQVM precompile interface and target precompile addresses.

use alloy_primitives::Bytes;
use pqvm_primitives::PQAddress;

pub const ML_DSA_65_VERIFY: PQAddress = numbered_precompile(1);
pub const SLH_DSA_SHA2_256F_VERIFY: PQAddress = numbered_precompile(2);
pub const ML_DSA_65_BATCH_VERIFY: PQAddress = numbered_precompile(3);
pub const BLAKE3_256: PQAddress = numbered_precompile(4);
pub const BLAKE3_512: PQAddress = numbered_precompile(5);
pub const PQADDRESS_DERIVE: PQAddress = numbered_precompile(6);

pub const fn numbered_precompile(n: u32) -> PQAddress {
    let bytes = n.to_be_bytes();
    let mut out = [0u8; 32];
    out[28] = bytes[0];
    out[29] = bytes[1];
    out[30] = bytes[2];
    out[31] = bytes[3];
    PQAddress(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecompileOutput {
    pub gas_used: u64,
    pub output: Bytes,
}

pub trait PrecompileSet {
    type Error: std::error::Error + Send + Sync + 'static;

    fn contains(&self, address: PQAddress) -> bool;

    fn execute(
        &self,
        address: PQAddress,
        input: &[u8],
        gas_limit: u64,
    ) -> Result<Option<PrecompileOutput>, Self::Error>;
}
