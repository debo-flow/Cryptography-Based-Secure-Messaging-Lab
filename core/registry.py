"""
Cryptographic Algorithm Registry.
"""
from dataclasses import dataclass
from typing import Dict

@dataclass
class AlgorithmMetadata:
    name: str
    category: str
    description: str
    planned_status: str
    milestone: str

ALGORITHM_REGISTRY: Dict[str, AlgorithmMetadata] = {
    "AES-128": AlgorithmMetadata("AES-128", "Symmetric", "Advanced Encryption Standard (128-bit)", "Implemented", "M03"),
    "AES-192": AlgorithmMetadata("AES-192", "Symmetric", "Advanced Encryption Standard (192-bit)", "Implemented", "M03"),
    "AES-256": AlgorithmMetadata("AES-256", "Symmetric", "Advanced Encryption Standard (256-bit)", "Implemented", "M03"),
    
    "AES-128-GCM": AlgorithmMetadata("AES-128-GCM", "AEAD", "AES Galois/Counter Mode (128-bit)", "Implemented", "M04"),
    "AES-192-GCM": AlgorithmMetadata("AES-192-GCM", "AEAD", "AES Galois/Counter Mode (192-bit)", "Implemented", "M04"),
    "AES-256-GCM": AlgorithmMetadata("AES-256-GCM", "AEAD", "AES Galois/Counter Mode (256-bit)", "Implemented", "M04"),
    
    "ChaCha20": AlgorithmMetadata("ChaCha20", "Symmetric Stream", "ChaCha20 Stream Cipher", "Planned", "M07"),
    "ChaCha20-Poly1305": AlgorithmMetadata("ChaCha20-Poly1305", "AEAD", "ChaCha20 with Poly1305 MAC", "Planned", "M08"),
    "Fernet": AlgorithmMetadata("Fernet", "Symmetric Auth", "Symmetric Authenticated Cryptography (Fernet)", "Planned", "M09"),
    
    "RSA": AlgorithmMetadata("RSA", "Asymmetric", "Rivest-Shamir-Adleman Algorithm", "Planned", "M05"),
    "RSA-OAEP": AlgorithmMetadata("RSA-OAEP", "Asymmetric", "RSA with Optimal Asymmetric Encryption Padding", "Planned", "M06"),
    "X25519": AlgorithmMetadata("X25519", "Key Exchange", "Elliptic-curve Diffie-Hellman", "Planned", "M12"),
    
    "PBKDF2": AlgorithmMetadata("PBKDF2", "KDF", "Password-Based Key Derivation Function 2", "Planned", "M14"),
    "Scrypt": AlgorithmMetadata("Scrypt", "KDF", "Scrypt Key Derivation Function", "Planned", "M14"),
    "Argon2id": AlgorithmMetadata("Argon2id", "KDF", "Argon2id Memory-Hard KDF", "Planned", "M14"),
    
    "RSA-PSS": AlgorithmMetadata("RSA-PSS", "Digital Signature", "RSA Probabilistic Signature Scheme", "Planned", "M16"),
    "Ed25519": AlgorithmMetadata("Ed25519", "Digital Signature", "Edwards-curve Digital Signature Algorithm", "Planned", "M16")
}
