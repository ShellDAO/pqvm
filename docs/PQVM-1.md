# PQVM-1 Specification Draft

PQVM-1 is the first executable specification target for the Shell-Chain
Post-Quantum Virtual Machine. It follows the English Shell-Chain white paper
unless this document explicitly records a correction that must be reflected
back into the paper.

## 1. Address model

`PQAddress` is a 32-byte value:

```text
PQAddress = BLAKE3(algo_id || public_key)[0:32]
```

- `algo_id = 0x01`: ML-DSA-65.
- `algo_id = 0x02`: SLH-DSA-SHA2-256f.
- Human rendering is `0x` followed by 64 lowercase hexadecimal characters.
- `PQAddress` is distinct from libp2p `PeerID`; the latter may share the same
  width but uses a separate derivation context.

## 2. Account model

PQVM has no externally owned accounts. Every account is a code account:

```text
Account = {
  nonce: u64,
  balance: U256,
  code_hash: BLAKE3Hash,
  storage_root: MerkleRoot
}
```

Transaction validity is determined by account code, normally through a
`validateSignature()` entrypoint. The reference `PQAccount` contract validates
ML-DSA-65 and SLH-DSA-SHA2-256f signatures through the native precompile suite.

## 3. Transaction model

`PQTx` carries signature material explicitly:

```text
PQTx {
  chain_id:   u64
  nonce:      u64
  max_fee:    U256
  gas_limit:  u64
  to:         PQAddress?   // null = contract creation
  value:      U256
  data:       bytes
  sig_type:   u8           // also the address-derivation algo_id
  public_key: Option<bytes>
  signature:  bytes
}
```

The signing payload binds `chain_id` and `sig_type` to prevent cross-chain
replay and algorithm substitution.

## 4. Retained execution semantics

PQVM keeps EVM-like semantics where they do not introduce classical
cryptographic assumptions:

- 1024-element stack of 256-bit words.
- 256-bit integer arithmetic.
- Linear byte-addressable memory.
- 256-bit storage keys and values.
- Call frames with isolated stack, memory, and gas counters.
- `KECCAK256` may be retained for Solidity storage-slot compatibility, but it
  is not a Shell-Chain security primitive.

Differential tests against revm are allowed only for retained semantics.

## 5. Removed semantics

PQVM removes the classical Ethereum cryptographic surface:

- No ECDSA account rule.
- No `ecrecover`.
- No BN256 precompiles.
- No standard Ethereum precompile table by default.
- `SELFDESTRUCT` has no destructive mode.

## 6. New PQ opcodes

| Opcode | Byte | Purpose |
|---|---:|---|
| `PQVERIFY` | `0xB0` | Verify a PQ signature. |
| `PQHASH` | `0xB1` | Compute BLAKE3-256 into memory. |
| `PQADDR` | `0xB2` | Derive a 32-byte `PQAddress` from `algo_id` and public key. |

## 7. PQ precompile suite

| Address | Name | Gas |
|---|---|---:|
| `0x00..01` | ML-DSA-65 Verify | 46,000 |
| `0x00..02` | SLH-DSA-SHA2-256f Verify | 2,300,000 |
| `0x00..03` | ML-DSA-65 Batch Verify | `12,000 * n` |
| `0x00..04` | BLAKE3-256 | `30 + 6/word` |
| `0x00..05` | BLAKE3-512 | `30 + 6/word` |
| `0x00..06` | PQAddress Derive | 200 |

Precompile addresses occupy the reserved low 32-bit range in full 32-byte
address form.

## 8. Gas model

- Block gas design target: 50,000,000.
- Shell-Chain block transaction hard cap: 500.
- A simple ML-DSA-65 transfer costs `21,000 + 46,000 = 67,000` gas.
- `50,000,000 / 67,000 ~= 746`, so the 500-transaction hard cap binds before
  gas for homogeneous simple-transfer blocks.

## 9. Open specification checks

These items require implementation-driven review before PQVM-1 is frozen:

1. Whether `KECCAK256` remains mandatory or becomes a compatibility feature.
2. Whether `CALLCODE` should be retained despite its legacy semantics.
3. Whether `PQVERIFY` should return `0/1` or trap with structured errors.
4. Whether first-use direct verification conflicts with "all accounts are code
   accounts" or should be modeled as reference `PQAccount` deployment.
5. Whether Shell-Chain consensus-layer signature prechecks are outside PQVM gas
   or charged through PQVM transaction validation.

