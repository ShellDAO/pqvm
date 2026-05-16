use alloy_primitives::{Bytes, U256};
use pqvm::gas;
use pqvm::precompiles::{
    BasicPqPrecompiles, PrecompileSet, BLAKE3_256, BLAKE3_512, ML_DSA_65_BATCH_VERIFY,
    ML_DSA_65_VERIFY, PQADDRESS_DERIVE, SLH_DSA_SHA2_256F_VERIFY,
};
use pqvm::{AlgoId, Env, Interpreter, InterpreterError, PQAddress, PQTx, PqvmDatabase};

const PQADDRESS_VECTORS: &str = include_str!("../../../tests/fixtures/pqaddress_vectors.txt");
const PQTX_VECTORS: &str = include_str!("../../../tests/fixtures/pqtx_vectors.txt");

#[test]
fn pqaddress_derivation_matches_golden_vectors() {
    let ml_dsa_key = fixture(PQADDRESS_VECTORS, "ml_dsa_65_public_key_ascii");
    let ml_dsa_address = PQAddress::derive(AlgoId::MlDsa65 as u8, ml_dsa_key.as_bytes());
    assert_eq!(
        ml_dsa_address.to_string(),
        fixture(PQADDRESS_VECTORS, "ml_dsa_65_public_key_address")
    );

    let slh_key = fixture(PQADDRESS_VECTORS, "slh_dsa_sha2_256f_public_key_ascii");
    let slh_address = PQAddress::derive(AlgoId::SlhDsaSha2256f as u8, slh_key.as_bytes());
    assert_eq!(
        slh_address.to_string(),
        fixture(PQADDRESS_VECTORS, "slh_dsa_sha2_256f_public_key_address")
    );
}

#[test]
fn precompile_addresses_match_golden_vectors() {
    assert_eq!(
        ML_DSA_65_VERIFY.to_string(),
        fixture(PQADDRESS_VECTORS, "precompile_ml_dsa_65_verify")
    );
    assert_eq!(
        SLH_DSA_SHA2_256F_VERIFY.to_string(),
        fixture(PQADDRESS_VECTORS, "precompile_slh_dsa_sha2_256f_verify")
    );
    assert_eq!(
        ML_DSA_65_BATCH_VERIFY.to_string(),
        fixture(PQADDRESS_VECTORS, "precompile_ml_dsa_65_batch_verify")
    );
    assert_eq!(
        BLAKE3_256.to_string(),
        fixture(PQADDRESS_VECTORS, "precompile_blake3_256")
    );
    assert_eq!(
        BLAKE3_512.to_string(),
        fixture(PQADDRESS_VECTORS, "precompile_blake3_512")
    );
    assert_eq!(
        PQADDRESS_DERIVE.to_string(),
        fixture(PQADDRESS_VECTORS, "precompile_pqaddress_derive")
    );
}

#[test]
fn pqtx_signing_payload_matches_golden_vector() {
    let tx = PQTx {
        chain_id: fixture(PQTX_VECTORS, "vector_0_chain_id").parse().unwrap(),
        nonce: fixture(PQTX_VECTORS, "vector_0_nonce").parse().unwrap(),
        max_fee: U256::from(
            fixture(PQTX_VECTORS, "vector_0_max_fee")
                .parse::<u64>()
                .unwrap(),
        ),
        gas_limit: fixture(PQTX_VECTORS, "vector_0_gas_limit").parse().unwrap(),
        to: Some(fixture(PQTX_VECTORS, "vector_0_to").parse().unwrap()),
        value: U256::from(
            fixture(PQTX_VECTORS, "vector_0_value")
                .parse::<u64>()
                .unwrap(),
        ),
        data: Bytes::copy_from_slice(fixture(PQTX_VECTORS, "vector_0_data_ascii").as_bytes()),
        sig_type: fixture(PQTX_VECTORS, "vector_0_sig_type").parse().unwrap(),
        public_key: Some(Bytes::copy_from_slice(
            fixture(PQTX_VECTORS, "vector_0_public_key_ascii").as_bytes(),
        )),
        signature: Bytes::copy_from_slice(
            fixture(PQTX_VECTORS, "vector_0_signature_ascii").as_bytes(),
        ),
    };

    assert_eq!(
        format!("0x{}", hex::encode(tx.signing_payload())),
        fixture(PQTX_VECTORS, "vector_0_signing_payload")
    );
}

#[test]
fn gas_constants_match_pqvm_1() {
    assert_eq!(gas::BLOCK_GAS_LIMIT, 50_000_000);
    assert_eq!(gas::MAX_TX_PER_BLOCK, 500);
    assert_eq!(gas::INTRINSIC_GAS_TX, 21_000);
    assert_eq!(gas::ML_DSA_65_VERIFY_GAS, 46_000);
    assert_eq!(gas::SLH_DSA_SHA2_256F_VERIFY_GAS, 2_300_000);
    assert_eq!(gas::ML_DSA_65_BATCH_VERIFY_GAS_PER_SIG, 12_000);
    assert_eq!(gas::BLAKE3_BASE_GAS, 30);
    assert_eq!(gas::BLAKE3_WORD_GAS, 6);
    assert_eq!(gas::PQADDRESS_DERIVE_GAS, 200);
}

#[test]
fn precompile_set_exposes_pqvm_1_precompiles() {
    let precompiles = BasicPqPrecompiles;

    assert!(precompiles.contains(ML_DSA_65_VERIFY));
    assert!(precompiles.contains(SLH_DSA_SHA2_256F_VERIFY));
    assert!(precompiles.contains(ML_DSA_65_BATCH_VERIFY));
    assert!(precompiles.contains(BLAKE3_256));
    assert!(precompiles.contains(BLAKE3_512));
    assert!(precompiles.contains(PQADDRESS_DERIVE));
}

#[test]
fn removed_callcode_is_rejected_by_conformance_fixture() {
    let mut db = EmptyDb;
    let mut interpreter = Interpreter::default();
    let err = interpreter
        .execute(&mut db, &env(), &tx(&[0xf2]))
        .unwrap_err();

    assert!(matches!(err, InterpreterError::RemovedOpcode("CALLCODE")));
}

fn fixture<'a>(content: &'a str, key: &str) -> &'a str {
    content
        .lines()
        .filter(|line| !line.trim_start().starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .find(|(candidate, _)| candidate.trim() == key)
        .map(|(_, value)| value.trim())
        .unwrap_or_else(|| panic!("missing fixture key: {key}"))
}

fn env() -> Env {
    Env {
        chain_id: 1,
        block_number: 0,
        coinbase: PQAddress::zero(),
        gas_limit: gas::BLOCK_GAS_LIMIT,
        timestamp: 0,
    }
}

fn tx(data: &[u8]) -> PQTx {
    PQTx {
        chain_id: 1,
        nonce: 0,
        max_fee: U256::ZERO,
        gas_limit: gas::BLOCK_GAS_LIMIT,
        to: None,
        value: U256::ZERO,
        data: Bytes::copy_from_slice(data),
        sig_type: AlgoId::MlDsa65 as u8,
        public_key: None,
        signature: Bytes::new(),
    }
}

#[derive(Debug, Default)]
struct EmptyDb;

impl PqvmDatabase for EmptyDb {
    type Error = std::convert::Infallible;

    fn account(&mut self, _address: PQAddress) -> Result<Option<pqvm::AccountInfo>, Self::Error> {
        Ok(None)
    }

    fn storage(&mut self, _address: PQAddress, _index: U256) -> Result<U256, Self::Error> {
        Ok(U256::ZERO)
    }

    fn block_hash(&mut self, _number: u64) -> Result<alloy_primitives::B256, Self::Error> {
        Ok(alloy_primitives::B256::ZERO)
    }

    fn write_account(&mut self, _: PQAddress, _: pqvm::AccountInfo) -> Result<(), Self::Error> {
        Ok(())
    }
    fn write_storage(&mut self, _: PQAddress, _: U256, _: U256) -> Result<(), Self::Error> {
        Ok(())
    }
    fn erase_account(&mut self, _: PQAddress) -> Result<(), Self::Error> {
        Ok(())
    }
    fn move_value(&mut self, _: PQAddress, _: PQAddress, _: U256) -> Result<(), Self::Error> {
        Ok(())
    }
    fn state_checkpoint(&mut self) -> usize {
        0
    }
    fn state_revert(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }
    fn state_commit(&mut self, _: usize) -> Result<(), Self::Error> {
        Ok(())
    }
}
