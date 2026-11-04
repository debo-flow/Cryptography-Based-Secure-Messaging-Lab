# Advanced E2EE Architecture (V2.0)

## Overview (Milestone 31)
The V2.0 End-to-End Encryption architecture introduces strict role isolation, transcript-bound handshakes, and cryptographic replay protection.

## 1. Identity & Authentication Layer
Unlike V1, which implicitly trusted public keys, V2.0 utilizes **Ed25519 Identity Keys**. These keys are long-term and must be verified out-of-band (e.g., via M23 QR Exchange). 

## 2. Transcript-Bound Handshake
The `HandshakeEngineV2` prevents MITM and Downgrade attacks by generating a **Transcript Hash**. This hash includes:
* Protocol Versions
* Ephemeral X25519 Keys
* Cryptographic Nonces
* Identity Fingerprints

Both Alice and Bob sign this transcript using their Ed25519 Identity Keys. If the transcript is modified in transit, the signature validation fails, immediately aborting the handshake.

## 3. Directional Key Derivation
A single shared secret is dangerous. V2.0 passes the X25519 shared secret and the Transcript Hash into an HKDF-SHA256 expansion to yield isolated, directional keys:
* `Initiator-TX` (Alice encrypts, Bob decrypts)
* `Responder-TX` (Bob encrypts, Alice decrypts)

## 4. Replay Protection & Sequence Monotonicity
Every `MessageEngineV2` payload includes a strictly monotonic integer `sequence_number` and a unique `message_id`. 
* The AEAD tag (AES-GCM / ChaCha20-Poly1305) cryptographically binds this metadata.
* The receiver tracks the highest seen sequence number and caches consumed message IDs.
* **Any attempt to replay an old message, duplicate an ID, or inject out-of-order packets is cryptographically rejected.**
