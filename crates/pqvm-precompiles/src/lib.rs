//! PQVM precompile interface and target precompile addresses.

use alloy_primitives::Bytes;
use pqcrypto_dilithium::dilithium3;
use pqcrypto_sphincsplus::sphincssha2256fsimple;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey};
use pqvm_gas::{
    BLAKE3_BASE_GAS, BLAKE3_WORD_GAS, ML_DSA_65_BATCH_VERIFY_GAS_PER_SIG, ML_DSA_65_VERIFY_GAS,
    PQADDRESS_DERIVE_GAS, SLH_DSA_SHA2_256F_VERIFY_GAS,
};
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
    #[error("batch input has trailing bytes")]
    BatchTrailingBytes,
}

impl PrecompileSet for BasicPqPrecompiles {
    type Error = PrecompileError;

    fn contains(&self, address: PQAddress) -> bool {
        matches!(
            address,
            ML_DSA_65_VERIFY
                | SLH_DSA_SHA2_256F_VERIFY
                | ML_DSA_65_BATCH_VERIFY
                | BLAKE3_256
                | BLAKE3_512
                | PQADDRESS_DERIVE
        )
    }

    fn execute(
        &self,
        address: PQAddress,
        input: &[u8],
        gas_limit: u64,
    ) -> Result<Option<PrecompileOutput>, Self::Error> {
        match address {
            ML_DSA_65_VERIFY => {
                charge(ML_DSA_65_VERIFY_GAS, gas_limit)?;
                Ok(Some(PrecompileOutput {
                    gas_used: ML_DSA_65_VERIFY_GAS,
                    output: bool_output(verify_ml_dsa_65(input)),
                }))
            }
            SLH_DSA_SHA2_256F_VERIFY => {
                charge(SLH_DSA_SHA2_256F_VERIFY_GAS, gas_limit)?;
                Ok(Some(PrecompileOutput {
                    gas_used: SLH_DSA_SHA2_256F_VERIFY_GAS,
                    output: bool_output(verify_slh_dsa_sha2_256f(input)),
                }))
            }
            ML_DSA_65_BATCH_VERIFY => {
                let (count, valid) = verify_ml_dsa_65_batch(input)?;
                let gas_used = ML_DSA_65_BATCH_VERIFY_GAS_PER_SIG.saturating_mul(count as u64);
                charge(gas_used, gas_limit)?;
                Ok(Some(PrecompileOutput {
                    gas_used,
                    output: bool_output(valid),
                }))
            }
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

fn verify_ml_dsa_65(input: &[u8]) -> bool {
    let pk_len = dilithium3::public_key_bytes();
    let sig_len = dilithium3::signature_bytes();
    if input.len() < pk_len + sig_len {
        return false;
    }

    let public_key = &input[..pk_len];
    let signature = &input[pk_len..pk_len + sig_len];
    let message = &input[pk_len + sig_len..];

    let Ok(pk) = dilithium3::PublicKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = dilithium3::DetachedSignature::from_bytes(signature) else {
        return false;
    };
    dilithium3::verify_detached_signature(&sig, message, &pk).is_ok()
}

fn verify_slh_dsa_sha2_256f(input: &[u8]) -> bool {
    let pk_len = sphincssha2256fsimple::public_key_bytes();
    let sig_len = sphincssha2256fsimple::signature_bytes();
    if input.len() < pk_len + sig_len {
        return false;
    }

    let public_key = &input[..pk_len];
    let signature = &input[pk_len..pk_len + sig_len];
    let message = &input[pk_len + sig_len..];

    let Ok(pk) = sphincssha2256fsimple::PublicKey::from_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = sphincssha2256fsimple::DetachedSignature::from_bytes(signature) else {
        return false;
    };
    sphincssha2256fsimple::verify_detached_signature(&sig, message, &pk).is_ok()
}

fn verify_ml_dsa_65_batch(input: &[u8]) -> Result<(usize, bool), PrecompileError> {
    let Some(count_bytes) = input.get(..4) else {
        return Ok((0, false));
    };
    let count = u32::from_be_bytes(count_bytes.try_into().expect("slice length checked")) as usize;
    let mut cursor = 4usize;
    let mut valid = true;

    for _ in 0..count {
        let Some(len_bytes) = input.get(cursor..cursor + 4) else {
            return Ok((count, false));
        };
        cursor += 4;
        let msg_len =
            u32::from_be_bytes(len_bytes.try_into().expect("slice length checked")) as usize;
        let pk_len = dilithium3::public_key_bytes();
        let sig_len = dilithium3::signature_bytes();
        let Some(end) = cursor
            .checked_add(pk_len)
            .and_then(|value| value.checked_add(sig_len))
            .and_then(|value| value.checked_add(msg_len))
        else {
            return Ok((count, false));
        };
        let Some(item) = input.get(cursor..end) else {
            return Ok((count, false));
        };
        valid &= verify_ml_dsa_65(item);
        cursor = end;
    }

    if cursor != input.len() {
        return Err(PrecompileError::BatchTrailingBytes);
    }

    Ok((count, valid))
}

fn bool_output(valid: bool) -> Bytes {
    Bytes::copy_from_slice(&[u8::from(valid)])
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_traits::sign::{DetachedSignature, PublicKey};

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
    fn ml_dsa_verify_precompile_accepts_valid_signature() {
        let (pk, sk) = dilithium3::keypair();
        let message = b"pqvm ml-dsa precompile";
        let sig = dilithium3::detached_sign(message, &sk);
        let mut input = Vec::new();
        input.extend_from_slice(pk.as_bytes());
        input.extend_from_slice(sig.as_bytes());
        input.extend_from_slice(message);

        let output = BasicPqPrecompiles
            .execute(ML_DSA_65_VERIFY, &input, ML_DSA_65_VERIFY_GAS)
            .unwrap()
            .unwrap();

        assert_eq!(output.gas_used, ML_DSA_65_VERIFY_GAS);
        assert_eq!(output.output.as_ref(), &[1]);
    }

    #[test]
    fn ml_dsa_verify_precompile_rejects_invalid_signature() {
        let (pk, sk) = dilithium3::keypair();
        let sig = dilithium3::detached_sign(b"message", &sk);
        let mut input = Vec::new();
        input.extend_from_slice(pk.as_bytes());
        input.extend_from_slice(sig.as_bytes());
        input.extend_from_slice(b"different message");

        let output = BasicPqPrecompiles
            .execute(ML_DSA_65_VERIFY, &input, ML_DSA_65_VERIFY_GAS)
            .unwrap()
            .unwrap();

        assert_eq!(output.output.as_ref(), &[0]);
    }

    #[test]
    fn slh_dsa_verify_precompile_accepts_valid_signature() {
        let (pk, sk) = sphincssha2256fsimple::keypair();
        let message = b"pqvm slh-dsa precompile";
        let sig = sphincssha2256fsimple::detached_sign(message, &sk);
        let mut input = Vec::new();
        input.extend_from_slice(pk.as_bytes());
        input.extend_from_slice(sig.as_bytes());
        input.extend_from_slice(message);

        let output = BasicPqPrecompiles
            .execute(
                SLH_DSA_SHA2_256F_VERIFY,
                &input,
                SLH_DSA_SHA2_256F_VERIFY_GAS,
            )
            .unwrap()
            .unwrap();

        assert_eq!(output.gas_used, SLH_DSA_SHA2_256F_VERIFY_GAS);
        assert_eq!(output.output.as_ref(), &[1]);
    }

    #[test]
    fn ml_dsa_batch_verify_accepts_valid_batch() {
        let message = b"batch message";
        let (pk, sk) = dilithium3::keypair();
        let sig = dilithium3::detached_sign(message, &sk);
        let mut input = Vec::new();
        input.extend_from_slice(&1u32.to_be_bytes());
        input.extend_from_slice(&(message.len() as u32).to_be_bytes());
        input.extend_from_slice(pk.as_bytes());
        input.extend_from_slice(sig.as_bytes());
        input.extend_from_slice(message);

        let output = BasicPqPrecompiles
            .execute(
                ML_DSA_65_BATCH_VERIFY,
                &input,
                ML_DSA_65_BATCH_VERIFY_GAS_PER_SIG,
            )
            .unwrap()
            .unwrap();

        assert_eq!(output.gas_used, ML_DSA_65_BATCH_VERIFY_GAS_PER_SIG);
        assert_eq!(output.output.as_ref(), &[1]);
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
