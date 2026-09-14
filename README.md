
# Gate Zero

Cryptographic execution governance for OT/ICS environments.

## What It Does

Gate Zero enforces pre-authorized, cryptographically signed commands at the instruction level — before execution reaches the controller. Every command requires a valid Ed25519-signed capability token with nanosecond expiry. No valid token, no execution.

## Architecture

- Ed25519 signed capability tokens with nanosecond expiry
- Brownfield-compatible enforcement proxy — no firmware changes required
- Hash-chained WAL audit log
- 2-second cryptographic heartbeat attestation loop
- Consequence-aware token issuance
- Shadow deception layer with attacker attribution
- Moving target key rotation
- Zero-allocation BLAKE2b Merkle audit frontier

## Stack

| Binary | Role |
|---|---|
| pure_core | Cryptographic validation engine |
| wal_writer | Hash-chained audit log writer |
| wal_recover | Audit log recovery and verification |
| gate0_signer | Token issuance authority |
| gate0_daemon | Enforcement proxy |
| gate0_client | Command submission client |

## Build

C11 · ARM64 · libsodium · Production validated

## Status

ARM64 bare-metal validation in progress on Raspberry Pi 5.
