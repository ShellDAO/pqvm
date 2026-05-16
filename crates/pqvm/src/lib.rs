//! Public facade for the Shell-Chain Post-Quantum Virtual Machine.

use alloy_primitives::U256;
use precompiles::{PrecompileSet, ML_DSA_65_VERIFY, SLH_DSA_SHA2_256F_VERIFY};

pub use pqvm_gas as gas;
pub use pqvm_interpreter::{
    opcode_info, Bytecode, Env, ExecutionResult, ExecutionStatus, FrameContext, GasMeter,
    Interpreter, InterpreterError, LogEntry, Memory, OpcodeInfo,
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
    pub logs: Vec<LogEntry>,
    pub state_diff: StateDiff,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockExecutionResult {
    pub gas_used: u64,
    pub receipts: Vec<TxReceipt>,
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
    #[error("transaction signature is invalid")]
    InvalidSignature,
    #[error("signature verification precompile failed: {0}")]
    SignaturePrecompile(String),
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Interpreter(#[from] InterpreterError),
}

#[derive(Debug, thiserror::Error)]
pub enum BlockExecutionError {
    #[error("block has {count} transactions, above hard cap {max}")]
    TooManyTransactions { count: usize, max: usize },
    #[error("block gas limit exceeded: used {used}, next tx {next}, limit {limit}")]
    BlockGasLimitExceeded { used: u64, next: u64, limit: u64 },
    #[error("transaction {index} failed: {source}")]
    Transaction {
        index: usize,
        #[source]
        source: TxExecutionError,
    },
}

pub fn execute_block(
    state: &mut PqvmState,
    env: &Env,
    txs: &[PQTx],
) -> Result<BlockExecutionResult, BlockExecutionError> {
    if txs.len() > gas::MAX_TX_PER_BLOCK {
        return Err(BlockExecutionError::TooManyTransactions {
            count: txs.len(),
            max: gas::MAX_TX_PER_BLOCK,
        });
    }

    let checkpoint = state.checkpoint();
    let mut receipts = Vec::with_capacity(txs.len());
    let mut gas_used = 0u64;

    for (index, tx) in txs.iter().enumerate() {
        let receipt = match execute_transaction(state, env, tx) {
            Ok(receipt) => receipt,
            Err(source) => {
                let _ = state.revert_to_checkpoint(checkpoint);
                return Err(BlockExecutionError::Transaction { index, source });
            }
        };
        let Some(next_gas_used) = gas_used.checked_add(receipt.gas_used) else {
            let _ = state.revert_to_checkpoint(checkpoint);
            return Err(BlockExecutionError::BlockGasLimitExceeded {
                used: gas_used,
                next: receipt.gas_used,
                limit: env.gas_limit,
            });
        };
        if next_gas_used > env.gas_limit {
            let _ = state.revert_to_checkpoint(checkpoint);
            return Err(BlockExecutionError::BlockGasLimitExceeded {
                used: gas_used,
                next: receipt.gas_used,
                limit: env.gas_limit,
            });
        }
        gas_used = next_gas_used;
        receipts.push(receipt);
    }

    state
        .discard_checkpoint(checkpoint)
        .map_err(|source| BlockExecutionError::Transaction {
            index: txs.len(),
            source: TxExecutionError::State(source),
        })?;

    Ok(BlockExecutionResult { gas_used, receipts })
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
    verify_transaction_signature(tx)?;
    let checkpoint = state.checkpoint();
    ensure_sender_account(state, sender, tx)?;
    validate_sender_account(state, sender, tx)?;

    if let Some(to) = tx.to {
        state.transfer(sender, to, tx.value)?;
    }

    fn verify_transaction_signature(tx: &PQTx) -> Result<(), TxExecutionError> {
        let public_key = tx
            .public_key
            .as_ref()
            .ok_or(TxExecutionError::MissingPublicKey)?;
        let precompile = match AlgoId::try_from(tx.sig_type)
            .map_err(|_| TxExecutionError::UnknownSignatureAlgorithm(tx.sig_type))?
        {
            AlgoId::MlDsa65 => ML_DSA_65_VERIFY,
            AlgoId::SlhDsaSha2256f => SLH_DSA_SHA2_256F_VERIFY,
        };
        let mut input = Vec::with_capacity(public_key.len() + tx.signature.len() + 32);
        input.extend_from_slice(public_key);
        input.extend_from_slice(&tx.signature);
        input.extend_from_slice(tx.signing_payload().as_slice());
        let output = precompiles::BasicPqPrecompiles
            .execute(precompile, &input, u64::MAX)
            .map_err(|err| TxExecutionError::SignaturePrecompile(err.to_string()))?
            .ok_or_else(|| TxExecutionError::SignaturePrecompile("missing verifier".into()))?;
        if output.output.first().copied() != Some(1) {
            return Err(TxExecutionError::InvalidSignature);
        }
        Ok(())
    }
    state.increment_nonce(sender)?;

    // Load the callee code from state; use tx.data as calldata.
    // For contract creation (tx.to == None), tx.data is the initcode.
    let (code, calldata) = if let Some(to) = tx.to {
        let acct_code = state
            .account_ref(to)
            .map(|a| a.code.to_vec())
            .unwrap_or_default();
        (acct_code, tx.data.clone())
    } else {
        // CREATE: initcode = tx.data; calldata is empty
        (tx.data.to_vec(), alloy_primitives::Bytes::new())
    };

    let sender_origin = sender;
    let ctx = FrameContext {
        code,
        calldata,
        caller: sender,
        address: tx.to.unwrap_or_else(|| {
            // Derive CREATE address from sender + nonce (nonce already incremented).
            let nonce = state.account_ref(sender).map_or(1u64, |a| a.nonce);
            create_address_from_nonce(sender, nonce.saturating_sub(1))
        }),
        value: tx.value,
        origin: sender_origin,
        is_static: false,
        depth: 0,
        gas_limit: tx.gas_limit.min(env.gas_limit),
    };

    let mut interpreter = Interpreter::default();
    let result = match interpreter.execute_frame(state, env, &ctx) {
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
        logs: result.logs,
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

/// Derive a `CREATE` contract address: `BLAKE3(0x00 || sender || nonce_be8)[0:32]`.
fn create_address_from_nonce(sender: PQAddress, nonce: u64) -> PQAddress {
    let mut h = blake3::Hasher::new();
    h.update(&[0x00]);
    h.update(sender.as_bytes());
    h.update(&nonce.to_be_bytes());
    PQAddress(*h.finalize().as_bytes())
}

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
            gas_limit: gas::BLOCK_GAS_LIMIT,
            timestamp: 0,
        }
    }

    fn make_tx(value: u64, data: &[u8], to: Option<PQAddress>) -> PQTx {
        let (pk, sk) = dilithium3::keypair();
        let mut tx = PQTx {
            chain_id: 1,
            nonce: 0,
            max_fee: U256::ZERO,
            gas_limit: gas::BLOCK_GAS_LIMIT,
            to,
            value: U256::from(value),
            data: Bytes::copy_from_slice(data),
            sig_type: AlgoId::MlDsa65 as u8,
            public_key: Some(Bytes::copy_from_slice(pk.as_bytes())),
            signature: Bytes::new(),
        };
        let signature = dilithium3::detached_sign(tx.signing_payload().as_slice(), &sk);
        tx.signature = Bytes::copy_from_slice(signature.as_bytes());
        tx
    }

    fn tx_with_keypair(value: u64, data: &[u8]) -> PQTx {
        make_tx(value, data, Some(PQAddress([0x22; 32])))
    }

    #[test]
    fn execute_transaction_transfers_value_and_returns_receipt() {
        let mut state = PqvmState::default();
        let tx = tx_with_keypair(40, &[0x00]);
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
        let tx = tx_with_keypair(0, &[0x00]);
        let sender = PQAddress::derive(tx.sig_type, tx.public_key.as_ref().unwrap());

        execute_transaction(&mut state, &env(), &tx).unwrap();

        let account = state.account_ref(sender).unwrap();
        assert_eq!(account.nonce, 1);
        assert_ne!(account.code_hash, alloy_primitives::B256::ZERO);
    }

    #[test]
    fn execute_transaction_reverts_state_on_interpreter_error() {
        let mut state = PqvmState::default();
        // Put CALLCODE (removed opcode) as the code of the target account.
        let target = PQAddress([0x22; 32]);
        state.insert_account(
            target,
            AccountInfo {
                code: Bytes::from_static(&[0xf2]), // CALLCODE opcode
                ..Default::default()
            },
        );
        // tx sends empty calldata to the target (which has bad code).
        let tx = tx_with_keypair(0, &[]);
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

    #[test]
    fn execute_transaction_rejects_invalid_signature() {
        let mut state = PqvmState::default();
        let mut tx = tx_with_keypair(0, &[0x00]);
        tx.signature = Bytes::from_static(b"invalid");

        let err = execute_transaction(&mut state, &env(), &tx).unwrap_err();

        assert!(matches!(err, TxExecutionError::InvalidSignature));
    }

    #[test]
    fn execute_block_returns_receipts_and_cumulative_gas() {
        let mut state = PqvmState::default();
        let tx = tx_with_keypair(0, &[0x00]);

        let result = execute_block(&mut state, &env(), &[tx]).unwrap();

        assert_eq!(result.receipts.len(), 1);
        assert_eq!(result.gas_used, result.receipts[0].gas_used);
    }

    #[test]
    fn execute_block_enforces_transaction_hard_cap() {
        let mut state = PqvmState::default();
        let txs = vec![tx_with_keypair(0, &[0x00]); gas::MAX_TX_PER_BLOCK + 1];

        let err = execute_block(&mut state, &env(), &txs).unwrap_err();

        assert!(matches!(
            err,
            BlockExecutionError::TooManyTransactions { count, max }
                if count == gas::MAX_TX_PER_BLOCK + 1 && max == gas::MAX_TX_PER_BLOCK
        ));
    }

    #[test]
    fn execute_block_reverts_all_transactions_on_failure() {
        let mut state = PqvmState::default();
        // [0x22;32] is the target for good tx (empty account → STOP).
        // [0x44;32] is the target for bad tx (CALLCODE code).
        let bad_target = PQAddress([0x44; 32]);
        state.insert_account(
            bad_target,
            AccountInfo {
                code: Bytes::from_static(&[0xf2]), // CALLCODE opcode
                ..Default::default()
            },
        );

        let good = make_tx(0, &[], Some(PQAddress([0x22; 32])));
        let bad = make_tx(0, &[], Some(bad_target));
        let good_sender = PQAddress::derive(good.sig_type, good.public_key.as_ref().unwrap());

        let err = execute_block(&mut state, &env(), &[good, bad]).unwrap_err();

        assert!(matches!(
            err,
            BlockExecutionError::Transaction {
                index: 1,
                source: TxExecutionError::Interpreter(InterpreterError::RemovedOpcode("CALLCODE"))
            }
        ));
        assert!(state.account_ref(good_sender).is_none());
    }
}
