//! State/database traits for PQVM.

use alloy_primitives::{Bytes, B256, U256};
use pqvm_primitives::PQAddress;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountInfo {
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: B256,
    pub code: Bytes,
}

/// Revm-inspired state boundary using PQ-native addresses.
pub trait PqvmDatabase {
    type Error: std::error::Error + Send + Sync + 'static;

    fn account(&mut self, address: PQAddress) -> Result<Option<AccountInfo>, Self::Error>;

    fn storage(&mut self, address: PQAddress, index: U256) -> Result<U256, Self::Error>;

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error>;
}
