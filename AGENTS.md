# PQVM Agent Notes

This repository implements the Shell-Chain Post-Quantum Virtual Machine.

The English Shell-Chain white paper is the technical source of truth for PQVM
behavior until the PQVM specification in this repository is complete. If the
implementation plan reveals a white-paper error or ambiguity, fix the white
paper first and keep the Chinese version aligned to English.

PQVM is a clean implementation modeled on revm's architecture. Do not preserve
EVM compatibility where it conflicts with the PQVM design: 20-byte addresses,
ECDSA account validity, `ecrecover`, BN256 precompiles, and classical crypto
surfaces are out of scope for the target VM.

