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

- current `shell_primitives::Address` is a current-network address,
- `pqvm_primitives::PQAddress` is a PQVM-native address,
- no `From` implementation should silently convert between them.

## Validation split

Current Shell-Chain performs consensus-layer PQ signature validation before EVM
execution. PQVM-1 keeps that split for block admission while also pricing
contract-visible `validateSignature()`, `PQVERIFY`, and PQ precompile execution
inside PQVM gas.

## Rollout gates

1. PQVM conformance suite passes.
2. Removed-opcode and removed-precompile tests pass.
3. 32-byte address RPC/SDK/wallet plan is complete.
4. White paper and PQVM-1 spec are synchronized.
5. A non-production genesis profile can select `execution = "pqvm"`.

