//! Public facade for the Shell-Chain Post-Quantum Virtual Machine.

use alloy_primitives::U256;

pub use pqvm_gas as gas;
pub use pqvm_interpreter::{
    opcode_info, Bytecode, Env, ExecutionResult, ExecutionStatus, GasMeter, Interpreter,
    InterpreterError, Memory, OpcodeInfo,
};
pub use pqvm_precompiles as precompiles;
pub use pqvm_primitives::{AlgoId, PQAddress, PQTx};
pub use pqvm_state::{AccountInfo, PqvmDatabase, PqvmState, StateDiff, StateError};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxReceipt {
    pub sender: PQAddress,
    pub status: ExecutionStatus,
    pub gas_used: u64,
    pub output: alloy_primitives::Bytes,
    pub state_diff: StateDiff,
}

#[derive(Debug, thiserror::Error)]
pub enum TxExecutionError {
    #[error(
        "transaction chain id {tx_chain_id} does not match environment chain id {env_chain_id}"
    )]
    ChainIdMismatch { tx_chain_id: u64, env_chain_id: u64 },
    #[error("transaction gas limit {tx_gas_limit} exceeds environment gas limit {env_gas_limit}")]
    GasLimitTooHigh {
        tx_gas_limit: u64,
        env_gas_limit: u64,
    },
    #[error("first-use transaction is missing public_key")]
    MissingPublicKey,
    #[error("unknown signature algorithm id: {0}")]
    UnknownSignatureAlgorithm(u8),
    #[error("sender nonce mismatch: expected {expected}, got {got}")]
    NonceMismatch { expected: u64, got: u64 },
    #[error("sender balance {balance} is below value {value}")]
    InsufficientBalance { balance: U256, value: U256 },
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Interpreter(#[from] InterpreterError),
}

pub fn execute_transaction(
    state: &mut PqvmState,
    env: &Env,
    tx: &PQTx,
) -> Result<TxReceipt, TxExecutionError> {
    if tx.chain_id != env.chain_id {
        return Err(TxExecutionError::ChainIdMismatch {
            tx_chain_id: tx.chain_id,
            env_chain_id: env.chain_id,
        });
    }
    if tx.gas_limit > env.gas_limit {
        return Err(TxExecutionError::GasLimitTooHigh {
            tx_gas_limit: tx.gas_limit,
            env_gas_limit: env.gas_limit,
        });
    }

    let sender = derive_sender(tx)?;
    let checkpoint = state.checkpoint();
    ensure_sender_account(state, sender, tx)?;
    validate_sender_account(state, sender, tx)?;

    if let Some(to) = tx.to {
        state.transfer(sender, to, tx.value)?;
    }
    state.increment_nonce(sender)?;

    let mut interpreter = Interpreter::default();
    let result = match interpreter.execute(state, env, tx) {
        Ok(result) => result,
        Err(err) => {
            state.revert_to_checkpoint(checkpoint)?;
            return Err(TxExecutionError::Interpreter(err));
        }
    };

    let state_diff = state.diff_from_checkpoint(checkpoint)?;
    state.discard_checkpoint(checkpoint)?;

    Ok(TxReceipt {
        sender,
        status: result.status,
        gas_used: result.gas_used,
        output: result.output,
        state_diff,
    })
}

fn derive_sender(tx: &PQTx) -> Result<PQAddress, TxExecutionError> {
    AlgoId::try_from(tx.sig_type)
        .map_err(|_| TxExecutionError::UnknownSignatureAlgorithm(tx.sig_type))?;
    let public_key = tx
        .public_key
        .as_ref()
        .ok_or(TxExecutionError::MissingPublicKey)?;
    Ok(PQAddress::derive(tx.sig_type, public_key))
}

fn ensure_sender_account(
    state: &mut PqvmState,
    sender: PQAddress,
    tx: &PQTx,
) -> Result<(), TxExecutionError> {
    if state.account_ref(sender).is_some() {
        return Ok(());
    }

    let public_key = tx
        .public_key
        .as_ref()
        .ok_or(TxExecutionError::MissingPublicKey)?;
    let code_hash = reference_pqaccount_code_hash(tx.sig_type, public_key);
    state.insert_account(
        sender,
        AccountInfo {
            nonce: 0,
            balance: U256::ZERO,
            code_hash,
            code: alloy_primitives::Bytes::new(),
        },
    );
    Ok(())
}

fn validate_sender_account(
    state: &PqvmState,
    sender: PQAddress,
    tx: &PQTx,
) -> Result<(), TxExecutionError> {
    let account = state
        .account_ref(sender)
        .ok_or(StateError::MissingAccount(sender))?;
    if account.nonce != tx.nonce {
        return Err(TxExecutionError::NonceMismatch {
            expected: account.nonce,
            got: tx.nonce,
        });
    }
    if account.balance < tx.value {
        return Err(TxExecutionError::InsufficientBalance {
            balance: account.balance,
            value: tx.value,
        });
    }
    Ok(())
}

fn reference_pqaccount_code_hash(sig_type: u8, public_key: &[u8]) -> alloy_primitives::B256 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"PQVM-1:ReferencePQAccount");
    hasher.update(&[sig_type]);
    hasher.update(public_key);
    alloy_primitives::B256::from_slice(hasher.finalize().as_bytes())
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
            gas_limit: gas::BLOCK_GAS_LIMIT,
            timestamp: 0,
        }
    }

    fn tx(public_key: &'static [u8], value: u64, data: &[u8]) -> PQTx {
        PQTx {
            chain_id: 1,
            nonce: 0,
            max_fee: U256::ZERO,
            gas_limit: gas::BLOCK_GAS_LIMIT,
            to: Some(PQAddress([0x22; 32])),
            value: U256::from(value),
            data: Bytes::copy_from_slice(data),
            sig_type: AlgoId::MlDsa65 as u8,
            public_key: Some(Bytes::from_static(public_key)),
            signature: Bytes::from_static(b"signature"),
        }
    }

    #[test]
    fn execute_transaction_transfers_value_and_returns_receipt() {
        let mut state = PqvmState::default();
        let tx = tx(b"public-key", 40, &[0x00]);
        let sender = PQAddress::derive(tx.sig_type, tx.public_key.as_ref().unwrap());
        state.insert_account(
            sender,
            AccountInfo {
                balance: U256::from(100),
                ..Default::default()
            },
        );

        let receipt = execute_transaction(&mut state, &env(), &tx).unwrap();

        assert_eq!(receipt.sender, sender);
        assert_eq!(receipt.status, ExecutionStatus::Success);
        assert_eq!(state.account_ref(sender).unwrap().nonce, 1);
        assert_eq!(state.account_ref(sender).unwrap().balance, U256::from(60));
        assert_eq!(
            state.account_ref(PQAddress([0x22; 32])).unwrap().balance,
            U256::from(40)
        );
        assert!(receipt.state_diff.accounts.contains_key(&sender));
    }

    #[test]
    fn execute_transaction_initializes_first_use_account() {
        let mut state = PqvmState::default();
        let tx = tx(b"new-key", 0, &[0x00]);
        let sender = PQAddress::derive(tx.sig_type, tx.public_key.as_ref().unwrap());

        execute_transaction(&mut state, &env(), &tx).unwrap();

        let account = state.account_ref(sender).unwrap();
        assert_eq!(account.nonce, 1);
        assert_ne!(account.code_hash, alloy_primitives::B256::ZERO);
    }

    #[test]
    fn execute_transaction_reverts_state_on_interpreter_error() {
        let mut state = PqvmState::default();
        let tx = tx(b"public-key", 0, &[0xf2]);
        let sender = PQAddress::derive(tx.sig_type, tx.public_key.as_ref().unwrap());
        state.insert_account(
            sender,
            AccountInfo {
                balance: U256::from(100),
                ..Default::default()
            },
        );

        let err = execute_transaction(&mut state, &env(), &tx).unwrap_err();

        assert!(matches!(
            err,
            TxExecutionError::Interpreter(InterpreterError::RemovedOpcode("CALLCODE"))
        ));
        assert_eq!(state.account_ref(sender).unwrap().nonce, 0);
    }
}
