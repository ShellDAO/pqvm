# Shell-Chain Adapter Plan

PQVM must integrate into `shell-chain` without changing existing network
behavior until PQVM conformance is stable. The adapter therefore starts as a
feature-gated execution backend, not a replacement for the current revm path.

## Boundary

The adapter should expose the same high-level responsibilities as the current
executor:

- validate a transaction envelope,
- execute a single transaction against world state,
- execute a block with cumulative gas accounting,
- produce receipts/logs/traces,
- commit state changes through Shell-Chain storage boundaries.

The standalone `pqvm` crate now exposes the first version of these boundaries:

- `execute_transaction(state, env, tx)` validates a `PQTx`, verifies its PQ
  signature, initializes first-use accounts, executes bytecode, and returns a
  receipt plus state diff.
- `execute_block(state, env, txs)` enforces the 500-transaction hard cap,
  accounts cumulative block gas, returns per-transaction receipts, and reverts
  the whole block on failure.

The Shell-Chain adapter should wrap these APIs rather than duplicating PQVM
admission logic.

## Execution profile

Shell-Chain should eventually select the backend from genesis/network config:

```text
execution = "revm"   // current networks
execution = "pqvm"   // PQVM-native networks
```

The default remains `revm` until PQVM conformance, migration rules, RPC shape,
SDK support, and explorer support are complete.

## Data conversion

The adapter must avoid implicit truncation between current 20-byte addresses and
PQVM 32-byte addresses. Any bridge type must be explicit:

- legacy `shell_primitives::Address` bridges the current revm-backed network path,
- `pqvm_primitives::PQAddress` is a PQVM-native address,
- no `From` implementation should silently convert between them.

## Validation split

Current Shell-Chain performs consensus-layer PQ signature validation before
execution in the revm-backed path. PQVM-1 keeps that split for block admission while also pricing
contract-visible `validateSignature()`, `PQVERIFY`, and PQ precompile execution
inside PQVM gas.

In the standalone `pqvm` crate, `PQTx` signature verification is performed before
state mutation and is treated as transaction admission. This matches the
consensus precheck split: block proposers/validators may pre-verify signatures,
while contracts still pay PQVM gas for explicit `PQVERIFY` opcodes and PQ
precompile calls.

## Adapter shape

The first non-production adapter should be deliberately thin:

```text
ShellChainPqvmAdapter {
  state: ShellChainStateBridge,
  env: pqvm::Env,
}
```

Responsibilities:

1. Convert a PQVM-native genesis/network profile into `pqvm::Env`.
2. Decode network transactions into `pqvm::PQTx` without accepting legacy
   20-byte addresses.
3. Implement a `PqvmDatabase` bridge over Shell-Chain account/storage backends.
4. Call `pqvm::execute_block`.
5. Convert `pqvm::TxReceipt` into the RPC/indexer receipt shape for PQVM-native
   networks.

Non-responsibilities for the first adapter:

- no migration of existing revm networks,
- no implicit `Address <-> PQAddress` conversion,
- no compatibility deployment of Ethereum precompiles,
- no default activation on public testnet/mainnet.

## Rollout gates

1. PQVM conformance suite passes.
2. Removed-opcode and removed-precompile tests pass.
3. 32-byte address RPC/SDK/wallet plan is complete.
4. White paper and PQVM-1 spec are synchronized.
5. A non-production genesis profile can select `execution = "pqvm"`.

Additional gates after the standalone executor work:

6. `CALL`, `DELEGATECALL`, `STATICCALL`, `CREATE`, and `CREATE2` semantics are
   specified for 32-byte `PQAddress` and covered by fixtures.
7. `SELFDESTRUCT` non-destructive behavior is covered by tests.
8. Receipt/log encoding for 32-byte addresses is fixed.
9. RPC transaction and receipt schemas are versioned for PQVM-native networks.
