# PQVM

PQVM is the Post-Quantum Virtual Machine for Shell-Chain.

The project is a clean Rust implementation modeled on revm's architecture
without being a fork of revm. It keeps the parts of an EVM-style execution
engine that are useful for developers--stack execution, 256-bit words, gas
metering, database abstraction, and deterministic receipts--while replacing the
classical cryptographic surface with Shell-Chain's PQ-native design.

## Design targets

- Native 32-byte `PQAddress`:
  `BLAKE3(algo_id || public_key)[0:32]`, rendered as `0x{64 hex}`.
- No ECDSA account rule and no `ecrecover`.
- No BN256 or other classical Ethereum crypto precompiles.
- Native account abstraction: account validity is code-defined.
- PQ-native opcodes: `PQVERIFY`, `PQHASH`, `PQADDR`.
- PQ precompile suite for ML-DSA-65, SLH-DSA-SHA2-256f, BLAKE3, and address
  derivation.
- Revm-inspired execution architecture, with differential tests only for
  retained EVM-identical semantics.

## Current status

This repository is an implementation scaffold. It defines the crate topology,
core PQ primitives, gas constants, state/precompile traits, and the initial
interpreter facade. Full opcode execution and Shell-Chain integration are next.

## Specification

- [`docs/PQVM-1.md`](docs/PQVM-1.md) is the current executable specification
  draft.

## Development checks

Run the workspace checks before submitting changes:

```bash
cargo fmt --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
```

## Conformance fixtures

The first PQVM-1 golden vectors live under `tests/fixtures/` and are exercised
by the facade crate integration tests:

- `pqaddress_vectors.txt`: PQAddress derivation and precompile address vectors.
- `pqtx_vectors.txt`: PQTx signing-payload vector.

These fixtures are intentionally small and stable; expand them whenever a
specification rule becomes executable.
