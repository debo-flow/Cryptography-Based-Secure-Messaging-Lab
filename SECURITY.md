# Security Policy and Limitations (v1.0.0)

## Supported Versions
Only the latest release (`v1.0.0`) receives security updates.

## Reporting a Vulnerability
If you discover a vulnerability, please open a standard GitHub issue. Since this is an educational project, public disclosure is acceptable and encouraged for collaborative learning.

## Cryptographic Guarantees & Limitations
**This is an educational software laboratory. It has NOT been subjected to an independent, professional cryptographic audit.** 

While it implements vetted algorithms (`AES-256-GCM`, `X25519`, `Ed25519`, `Argon2id`), you should **NOT** use this software to protect real-world, high-stakes sensitive data.

### Known Limitations:
1. **Memory Zeroization:** Python's memory manager and garbage collector make forensic memory zeroization impossible to guarantee. Extracting keys from RAM via a cold-boot attack remains a valid threat model.
2. **Side-Channel Attacks:** This software does not implement extensive constant-time algorithms at the Python layer (relying entirely on the underlying `cryptography` C-bindings).
3. **Out-of-Band (OOB) Authentication:** E2EE Identity verification assumes the user correctly scans and verifies the QR code out-of-band. If the OOB channel is compromised, MITM is possible.
