//! PQVM precompile interface and target precompile addresses.

use alloy_primitives::Bytes;
use pqvm_gas::{BLAKE3_BASE_GAS, BLAKE3_WORD_GAS, PQADDRESS_DERIVE_GAS};
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

#[derive(Clone, Debug, Default)]
pub struct BasicPqPrecompiles;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PrecompileError {
    #[error("out of gas: required {required}, limit {limit}")]
    OutOfGas { required: u64, limit: u64 },
    #[error("missing algorithm id for PQAddress derivation")]
    MissingAlgoId,
}

impl PrecompileSet for BasicPqPrecompiles {
    type Error = PrecompileError;

    fn contains(&self, address: PQAddress) -> bool {
        matches!(address, BLAKE3_256 | BLAKE3_512 | PQADDRESS_DERIVE)
    }

    fn execute(
        &self,
        address: PQAddress,
        input: &[u8],
        gas_limit: u64,
    ) -> Result<Option<PrecompileOutput>, Self::Error> {
        match address {
            BLAKE3_256 => {
                let gas_used = blake3_gas(input.len());
                charge(gas_used, gas_limit)?;
                Ok(Some(PrecompileOutput {
                    gas_used,
                    output: Bytes::copy_from_slice(blake3::hash(input).as_bytes()),
                }))
            }
            BLAKE3_512 => {
                let gas_used = blake3_gas(input.len());
                charge(gas_used, gas_limit)?;
                let mut hasher = blake3::Hasher::new();
                hasher.update(input);
                let mut output = [0u8; 64];
                hasher.finalize_xof().fill(&mut output);
                Ok(Some(PrecompileOutput {
                    gas_used,
                    output: Bytes::copy_from_slice(&output),
                }))
            }
            PQADDRESS_DERIVE => {
                charge(PQADDRESS_DERIVE_GAS, gas_limit)?;
                let Some((&algo_id, public_key)) = input.split_first() else {
                    return Err(PrecompileError::MissingAlgoId);
                };
                let address = PQAddress::derive(algo_id, public_key);
                Ok(Some(PrecompileOutput {
                    gas_used: PQADDRESS_DERIVE_GAS,
                    output: Bytes::copy_from_slice(address.as_bytes()),
                }))
            }
            _ => Ok(None),
        }
    }
}

fn blake3_gas(input_len: usize) -> u64 {
    let words = input_len.div_ceil(32) as u64;
    BLAKE3_BASE_GAS + BLAKE3_WORD_GAS * words
}

fn charge(required: u64, limit: u64) -> Result<(), PrecompileError> {
    if required > limit {
        return Err(PrecompileError::OutOfGas { required, limit });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blake3_256_precompile_hashes_input() {
        let precompiles = BasicPqPrecompiles;
        let output = precompiles
            .execute(BLAKE3_256, b"abc", 1_000)
            .unwrap()
            .unwrap();
        assert_eq!(output.gas_used, 36);
        assert_eq!(output.output.as_ref(), blake3::hash(b"abc").as_bytes());
    }

    #[test]
    fn pqaddress_derive_precompile_outputs_32_bytes() {
        let precompiles = BasicPqPrecompiles;
        let mut input = vec![0x01];
        input.extend_from_slice(b"public-key");
        let output = precompiles
            .execute(PQADDRESS_DERIVE, &input, 1_000)
            .unwrap()
            .unwrap();
        assert_eq!(output.gas_used, PQADDRESS_DERIVE_GAS);
        assert_eq!(output.output.len(), 32);
        assert_eq!(
            output.output.as_ref(),
            PQAddress::derive(0x01, b"public-key").as_bytes()
        );
    }

    #[test]
    fn out_of_gas_is_reported() {
        let precompiles = BasicPqPrecompiles;
        let err = precompiles.execute(BLAKE3_256, b"abc", 1).unwrap_err();
        assert_eq!(
            err,
            PrecompileError::OutOfGas {
                required: 36,
                limit: 1
            }
        );
    }
}
