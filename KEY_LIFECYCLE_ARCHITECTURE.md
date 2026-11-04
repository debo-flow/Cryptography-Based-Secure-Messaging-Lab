# Key Lifecycle Management Architecture (M33)

## Overview
Milestone 33 introduces a centralized governance framework for cryptographic keys. Instead of keys existing statically until manually deleted, keys now move through a strict state machine: `ACTIVE` -> `ROTATED` -> `EXPIRED` / `REVOKED` / `COMPROMISED`.

## Key Rotation
When a key is rotated via the `KeyLifecycleManager`:
1. A new, cryptographically secure key of the exact same algorithm is generated.
2. The old key's status is changed to `ROTATED`.
3. **The old key is NOT deleted.** It remains in the KMS to facilitate historical decryption (e.g., reading a file encrypted 2 years ago).
4. The new key takes over all *new* encryption operations.
5. `lifecycle_versions` tracks the parent-child lineage so a complete timeline can be audited.

## Key Compromise Response
If a key is marked as `COMPROMISED`:
1. The `KeyDependencyAnalyzer` maps its blast radius. For example, if an Ed25519 Identity Key is compromised, all E2EE sessions established by that identity are flagged.
2. Cryptographic operations (both encryption and historical decryption) are hard-blocked by default using this key, unless overridden by an explicit forensic policy.

## Secure Backup and Recovery
To prevent catastrophic data loss without compromising security:
1. The raw binary key material (extracted from RAM) is serialized.
2. The payload is encrypted using the M14 Password-Based Encryption engine (`Argon2id` Key Derivation + `AES-256-GCM`).
3. Only the heavily encrypted JSON envelope is stored in the `lifecycle_backups` SQLite table.
4. During recovery, the user must provide the exact strong password to unwrap the AES-GCM envelope and reload the binary material into the KMS RAM.
