"""
Cryptographic Algorithm Registry (Final M30 Release).
Tracks supported cryptographic primitives, algorithms, and application modules.
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
    "AES-256": AlgorithmMetadata("AES-256", "Symmetric", "Advanced Encryption Standard (256-bit)", "Implemented", "M03"),
    "AES-256-GCM": AlgorithmMetadata("AES-256-GCM", "AEAD", "AES Galois/Counter Mode (256-bit)", "Implemented", "M04"),
    "ChaCha20-Poly1305": AlgorithmMetadata("ChaCha20-Poly1305", "AEAD", "ChaCha20 with Poly1305 MAC", "Implemented", "M08"),
    "Fernet": AlgorithmMetadata("Fernet", "Symmetric Auth", "Symmetric Authenticated Cryptography (Fernet)", "Implemented", "M09"),
    "RSA-OAEP-SHA256": AlgorithmMetadata("RSA-OAEP-SHA256", "Asymmetric Enc", "RSA OAEP with SHA-256", "Implemented", "M06"),
    "Hybrid-RSA-AES": AlgorithmMetadata("Hybrid-RSA-AES", "Hybrid AEAD", "RSA-OAEP KEM + AES-GCM DEM", "Implemented", "M10"),
    "ECC-SECP256R1": AlgorithmMetadata("ECC-SECP256R1", "Asymmetric", "Elliptic Curve Cryptography", "Implemented", "M11"),
    "X25519": AlgorithmMetadata("X25519", "Key Exchange", "Elliptic-curve Diffie-Hellman", "Implemented", "M11"),
    "HKDF-SHA256": AlgorithmMetadata("HKDF-SHA256", "KDF", "HMAC-based Extract-and-Expand Key Derivation", "Implemented", "M12"),
    "PBKDF2-HMAC-SHA256": AlgorithmMetadata("PBKDF2-HMAC-SHA256", "KDF", "Password-Based Key Derivation Function 2", "Implemented", "M14"),
    "Scrypt": AlgorithmMetadata("Scrypt", "KDF", "Memory-Hard Scrypt Key Derivation Function", "Implemented", "M14"),
    "Argon2id": AlgorithmMetadata("Argon2id", "KDF", "Argon2id Memory/Time-Hard KDF", "Implemented", "M14"),
    "RSA-PSS": AlgorithmMetadata("RSA-PSS", "Digital Signature", "RSA Probabilistic Signature Scheme", "Implemented", "M16"),
    "Ed25519": AlgorithmMetadata("Ed25519", "Digital Signature", "Edwards-curve Digital Signature Algorithm", "Implemented", "M16"),
    "HMAC-SHA256": AlgorithmMetadata("HMAC-SHA256", "Authentication", "Hash-based Message Authentication Code", "Implemented", "M17"),
    "AKE-Protocol": AlgorithmMetadata("AKE", "Protocol", "Authenticated Key Exchange", "Implemented", "M19"),
    "File-AEAD": AlgorithmMetadata("File-AEAD", "File Encryption", "AEAD File Package Envelope", "Implemented", "M21"),
    "KME-Engine": AlgorithmMetadata("KME", "Key Management", "Advanced Cryptographic Key Management System", "Implemented", "M22"),
    "QR-Identity": AlgorithmMetadata("QR-Identity", "Out-of-Band Trust", "QR Public Key Exchange System", "Implemented", "M23"),
    "Integrity-Analyzer": AlgorithmMetadata("Integrity", "Security Analysis", "Message Integrity & Security Analyzer", "Implemented", "M24"),
    "Comparison-Engine": AlgorithmMetadata("Compare", "Analysis", "Algorithm Comparison Engine", "Implemented", "M25"),
    "Advanced-Benchmark": AlgorithmMetadata("Benchmark", "Analysis", "Statistically Rigorous Profiling Engine", "Implemented", "M26"),
    "Security-Auditor": AlgorithmMetadata("Audit", "Analysis", "Defensive Security Posture Dashboard", "Implemented", "M27"),
    "Validation-Framework": AlgorithmMetadata("Testing", "Assurance", "Property-Based CI/CD Test Runner", "Implemented", "M28"),
    "System-Integration": AlgorithmMetadata("Integration", "Architecture", "M30 Production Release Consolidation", "Implemented", "M30")
}
