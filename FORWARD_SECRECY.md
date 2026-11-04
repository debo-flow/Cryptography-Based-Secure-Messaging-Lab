# Forward Secrecy & Post-Compromise Security (M32)

## What is Forward Secrecy (FS)?
Forward Secrecy guarantees that if a long-term key (like an Identity Key or a Master Storage Key) is compromised in the future, past communications remain secure. 
This is achieved by **never** using long-term keys to directly encrypt messages. Instead, we use **Ephemeral Diffie-Hellman (X25519)** keys to negotiate temporary session keys, which are deleted immediately after use.

## The Cryptographic Ratchet
This lab implements a KDF (Key Derivation Function) Ratchet. 
* Every time a message is sent, the `ChainKey` is passed through an `HKDF`. 
* This HKDF derives a `MessageKey` (used to encrypt the actual payload) and a **NEW** `ChainKey`.
* The old `ChainKey` is wiped from memory.

Because HKDF is a one-way function, an attacker who compromises the current `ChainKey` cannot mathematically reverse it to find older keys. This provides Perfect Forward Secrecy at a per-message level.

## Post-Compromise Security (PCS)
If an attacker compromises your device *right now*, they possess your current `ChainKey` and can decrypt future messages.
PCS solves this by injecting a *new* Ephemeral Diffie-Hellman exchange into the Ratchet. The resulting fresh shared secret is mixed into the Root Key, breaking the attacker's chain of knowledge and restoring security for all subsequent messages.
