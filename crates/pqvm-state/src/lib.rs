//! State/database traits for PQVM.

use alloy_primitives::{Bytes, B256, U256};
use pqvm_primitives::PQAddress;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AccountInfo {
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: B256,
    pub code: Bytes,
}

/// Revm-inspired state boundary using PQ-native addresses.
///
/// Includes read, write, and checkpoint operations so the interpreter can
/// implement SSTORE, CALL value transfers, CREATE, and sub-call rollback
/// without knowing the concrete state type.
pub trait PqvmDatabase {
    type Error: std::error::Error + Send + Sync + 'static;

    // ── reads ──────────────────────────────────────────────────────────────

    fn account(&mut self, address: PQAddress) -> Result<Option<AccountInfo>, Self::Error>;

    fn storage(&mut self, address: PQAddress, index: U256) -> Result<U256, Self::Error>;

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error>;

    // ── writes ─────────────────────────────────────────────────────────────

    /// Upsert an account.
    fn write_account(
        &mut self,
        address: PQAddress,
        account: AccountInfo,
    ) -> Result<(), Self::Error>;

    /// Set a storage slot (zero value deletes the slot).
    fn write_storage(
        &mut self,
        address: PQAddress,
        index: U256,
        value: U256,
    ) -> Result<(), Self::Error>;

    /// Delete an account and its storage.
    fn erase_account(&mut self, address: PQAddress) -> Result<(), Self::Error>;

    /// Transfer value between two accounts.  Creates the recipient if absent.
    fn move_value(
        &mut self,
        from: PQAddress,
        to: PQAddress,
        value: U256,
    ) -> Result<(), Self::Error>;

    // ── checkpointing ──────────────────────────────────────────────────────

    /// Snapshot the current state; returns an opaque checkpoint id.
    fn state_checkpoint(&mut self) -> usize;

    /// Roll back to a previously taken checkpoint.
    fn state_revert(&mut self, checkpoint: usize) -> Result<(), Self::Error>;

    /// Commit (discard) a checkpoint, making changes permanent.
    fn state_commit(&mut self, checkpoint: usize) -> Result<(), Self::Error>;
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StateDiff {
    pub accounts: BTreeMap<PQAddress, Option<AccountInfo>>,
    pub storage: BTreeMap<(PQAddress, U256), U256>,
    pub deleted_accounts: BTreeSet<PQAddress>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PqvmState {
    accounts: BTreeMap<PQAddress, AccountInfo>,
    storage: BTreeMap<(PQAddress, U256), U256>,
    block_hashes: BTreeMap<u64, B256>,
    checkpoints: Vec<StateSnapshot>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct StateSnapshot {
    accounts: BTreeMap<PQAddress, AccountInfo>,
    storage: BTreeMap<(PQAddress, U256), U256>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum StateError {
    #[error("missing account: {0}")]
    MissingAccount(PQAddress),
    #[error("insufficient balance in {address}: required {required}, available {available}")]
    InsufficientBalance {
        address: PQAddress,
        required: U256,
        available: U256,
    },
    #[error("invalid checkpoint: {0}")]
    InvalidCheckpoint(usize),
}

impl PqvmState {
    pub fn account_ref(&self, address: PQAddress) -> Option<&AccountInfo> {
        self.accounts.get(&address)
    }

    pub fn account_mut(&mut self, address: PQAddress) -> Option<&mut AccountInfo> {
        self.accounts.get_mut(&address)
    }

    pub fn insert_account(&mut self, address: PQAddress, account: AccountInfo) {
        self.accounts.insert(address, account);
    }

    pub fn remove_account(&mut self, address: PQAddress) -> Option<AccountInfo> {
        self.storage
            .retain(|(storage_address, _), _| *storage_address != address);
        self.accounts.remove(&address)
    }

    pub fn increment_nonce(&mut self, address: PQAddress) -> Result<u64, StateError> {
        let account = self
            .accounts
            .get_mut(&address)
            .ok_or(StateError::MissingAccount(address))?;
        account.nonce = account.nonce.saturating_add(1);
        Ok(account.nonce)
    }

    pub fn transfer(
        &mut self,
        from: PQAddress,
        to: PQAddress,
        value: U256,
    ) -> Result<(), StateError> {
        if value.is_zero() {
            self.accounts.entry(to).or_default();
            return Ok(());
        }

        let from_account = self
            .accounts
            .get_mut(&from)
            .ok_or(StateError::MissingAccount(from))?;
        if from_account.balance < value {
            return Err(StateError::InsufficientBalance {
                address: from,
                required: value,
                available: from_account.balance,
            });
        }
        from_account.balance -= value;

        self.accounts.entry(to).or_default().balance += value;
        Ok(())
    }

    pub fn set_storage(&mut self, address: PQAddress, index: U256, value: U256) {
        if value.is_zero() {
            self.storage.remove(&(address, index));
        } else {
            self.storage.insert((address, index), value);
        }
    }

    pub fn set_block_hash(&mut self, number: u64, hash: B256) {
        self.block_hashes.insert(number, hash);
    }

    pub fn checkpoint(&mut self) -> usize {
        let id = self.checkpoints.len();
        self.checkpoints.push(StateSnapshot {
            accounts: self.accounts.clone(),
            storage: self.storage.clone(),
        });
        id
    }

    pub fn revert_to_checkpoint(&mut self, checkpoint: usize) -> Result<(), StateError> {
        let snapshot = self
            .checkpoints
            .get(checkpoint)
            .cloned()
            .ok_or(StateError::InvalidCheckpoint(checkpoint))?;
        self.accounts = snapshot.accounts;
        self.storage = snapshot.storage;
        self.checkpoints.truncate(checkpoint);
        Ok(())
    }

    pub fn discard_checkpoint(&mut self, checkpoint: usize) -> Result<(), StateError> {
        if checkpoint >= self.checkpoints.len() {
            return Err(StateError::InvalidCheckpoint(checkpoint));
        }
        self.checkpoints.truncate(checkpoint);
        Ok(())
    }

    pub fn diff_from_checkpoint(&self, checkpoint: usize) -> Result<StateDiff, StateError> {
        let snapshot = self
            .checkpoints
            .get(checkpoint)
            .ok_or(StateError::InvalidCheckpoint(checkpoint))?;

        let mut diff = StateDiff::default();
        for (address, account) in &self.accounts {
            if snapshot.accounts.get(address) != Some(account) {
                diff.accounts.insert(*address, Some(account.clone()));
            }
        }
        for address in snapshot.accounts.keys() {
            if !self.accounts.contains_key(address) {
                diff.accounts.insert(*address, None);
                diff.deleted_accounts.insert(*address);
            }
        }
        for (slot, value) in &self.storage {
            if snapshot.storage.get(slot) != Some(value) {
                diff.storage.insert(*slot, *value);
            }
        }
        for slot in snapshot.storage.keys() {
            if !self.storage.contains_key(slot) {
                diff.storage.insert(*slot, U256::ZERO);
            }
        }

        Ok(diff)
    }
}

impl PqvmDatabase for PqvmState {
    type Error = StateError;

    fn account(&mut self, address: PQAddress) -> Result<Option<AccountInfo>, StateError> {
        Ok(self.accounts.get(&address).cloned())
    }

    fn storage(&mut self, address: PQAddress, index: U256) -> Result<U256, StateError> {
        Ok(self
            .storage
            .get(&(address, index))
            .copied()
            .unwrap_or_default())
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, StateError> {
        Ok(self.block_hashes.get(&number).copied().unwrap_or_default())
    }

    fn write_account(
        &mut self,
        address: PQAddress,
        account: AccountInfo,
    ) -> Result<(), StateError> {
        self.accounts.insert(address, account);
        Ok(())
    }

    fn write_storage(
        &mut self,
        address: PQAddress,
        index: U256,
        value: U256,
    ) -> Result<(), StateError> {
        self.set_storage(address, index, value);
        Ok(())
    }

    fn erase_account(&mut self, address: PQAddress) -> Result<(), StateError> {
        self.remove_account(address);
        Ok(())
    }

    fn move_value(
        &mut self,
        from: PQAddress,
        to: PQAddress,
        value: U256,
    ) -> Result<(), StateError> {
        self.transfer(from, to, value)
    }

    fn state_checkpoint(&mut self) -> usize {
        self.checkpoint()
    }

    fn state_revert(&mut self, checkpoint: usize) -> Result<(), StateError> {
        self.revert_to_checkpoint(checkpoint)
    }

    fn state_commit(&mut self, checkpoint: usize) -> Result<(), StateError> {
        self.discard_checkpoint(checkpoint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(n: u8) -> PQAddress {
        PQAddress([n; 32])
    }

    #[test]
    fn state_reads_accounts_storage_and_block_hashes() {
        let mut state = PqvmState::default();
        state.insert_account(
            address(1),
            AccountInfo {
                nonce: 7,
                balance: U256::from(100),
                code_hash: B256::ZERO,
                code: Bytes::from_static(b"code"),
            },
        );
        state.set_storage(address(1), U256::from(2), U256::from(3));
        state.set_block_hash(10, B256::repeat_byte(0xaa));

        assert_eq!(state.account(address(1)).unwrap().unwrap().nonce, 7);
        assert_eq!(
            state.storage(address(1), U256::from(2)).unwrap(),
            U256::from(3)
        );
        assert_eq!(state.block_hash(10).unwrap(), B256::repeat_byte(0xaa));
    }

    #[test]
    fn transfer_updates_balances_and_creates_recipient() {
        let mut state = PqvmState::default();
        state.insert_account(
            address(1),
            AccountInfo {
                balance: U256::from(100),
                ..Default::default()
            },
        );

        state
            .transfer(address(1), address(2), U256::from(40))
            .unwrap();

        assert_eq!(
            state.account_ref(address(1)).unwrap().balance,
            U256::from(60)
        );
        assert_eq!(
            state.account_ref(address(2)).unwrap().balance,
            U256::from(40)
        );
    }

    #[test]
    fn checkpoint_can_revert_changes() {
        let mut state = PqvmState::default();
        state.insert_account(
            address(1),
            AccountInfo {
                balance: U256::from(100),
                ..Default::default()
            },
        );
        let checkpoint = state.checkpoint();
        state
            .transfer(address(1), address(2), U256::from(40))
            .unwrap();

        state.revert_to_checkpoint(checkpoint).unwrap();

        assert_eq!(
            state.account_ref(address(1)).unwrap().balance,
            U256::from(100)
        );
        assert!(state.account_ref(address(2)).is_none());
    }

    #[test]
    fn diff_reports_account_and_storage_changes() {
        let mut state = PqvmState::default();
        state.insert_account(address(1), AccountInfo::default());
        let checkpoint = state.checkpoint();
        state.increment_nonce(address(1)).unwrap();
        state.set_storage(address(1), U256::from(1), U256::from(2));

        let diff = state.diff_from_checkpoint(checkpoint).unwrap();

        assert_eq!(
            diff.accounts
                .get(&address(1))
                .and_then(|account| account.as_ref())
                .unwrap()
                .nonce,
            1
        );
        assert_eq!(
            diff.storage.get(&(address(1), U256::from(1))).copied(),
            Some(U256::from(2))
        );
    }
}
