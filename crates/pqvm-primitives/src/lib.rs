//! PQVM primitive types.

use alloy_primitives::{Bytes, B256, U256};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

pub use alloy_primitives::{Bytes as PqBytes, B256 as PqHash, U256 as PqU256};

/// Native 32-byte Shell-Chain PQVM address.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
)]
pub struct PQAddress(pub [u8; 32]);

impl PQAddress {
    /// Derive a PQ-native address from an algorithm domain byte and serialized public key.
    pub fn derive(algo_id: u8, public_key: &[u8]) -> Self {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&[algo_id]);
        hasher.update(public_key);
        let digest = hasher.finalize();
        Self(*digest.as_bytes())
    }

    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for PQAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{}", hex::encode(self.0))
    }
}

impl FromStr for PQAddress {
    type Err = PrimitiveError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        let hex = input
            .strip_prefix("0x")
            .ok_or(PrimitiveError::AddressMissingHexPrefix)?;
        if hex.len() != 64 {
            return Err(PrimitiveError::AddressLength { got: hex.len() });
        }
        let mut out = [0u8; 32];
        hex::decode_to_slice(hex, &mut out).map_err(|_| PrimitiveError::InvalidHex)?;
        Ok(Self(out))
    }
}

/// PQ signature algorithm domain byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum AlgoId {
    MlDsa65 = 0x01,
    SlhDsaSha2256f = 0x02,
}

impl TryFrom<u8> for AlgoId {
    type Error = PrimitiveError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Self::MlDsa65),
            0x02 => Ok(Self::SlhDsaSha2256f),
            other => Err(PrimitiveError::UnknownAlgoId(other)),
        }
    }
}

/// PQVM transaction envelope used by the target VM.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PQTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_fee: U256,
    pub gas_limit: u64,
    pub to: Option<PQAddress>,
    pub value: U256,
    pub data: Bytes,
    pub sig_type: u8,
    pub public_key: Option<Bytes>,
    pub signature: Bytes,
}

impl PQTx {
    pub fn signing_payload(&self) -> B256 {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.chain_id.to_be_bytes());
        hasher.update(&self.nonce.to_be_bytes());
        hasher.update(&self.max_fee.to_be_bytes::<32>());
        hasher.update(&self.gas_limit.to_be_bytes());
        match self.to {
            Some(addr) => hasher.update(addr.as_bytes()),
            None => hasher.update(&[0u8; 32]),
        };
        hasher.update(&self.value.to_be_bytes::<32>());
        hasher.update(&self.data);
        hasher.update(&[self.sig_type]);
        B256::from_slice(hasher.finalize().as_bytes())
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PrimitiveError {
    #[error("PQAddress must start with 0x")]
    AddressMissingHexPrefix,
    #[error("PQAddress hex length must be 64 chars, got {got}")]
    AddressLength { got: usize },
    #[error("invalid hex")]
    InvalidHex,
    #[error("unknown PQ algorithm id: {0}")]
    UnknownAlgoId(u8),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pq_address_roundtrip_0x64() {
        let addr = PQAddress::derive(AlgoId::MlDsa65 as u8, b"public-key");
        let rendered = addr.to_string();
        assert!(rendered.starts_with("0x"));
        assert_eq!(rendered.len(), 66);
        assert_eq!(rendered.parse::<PQAddress>().unwrap(), addr);
    }
}
