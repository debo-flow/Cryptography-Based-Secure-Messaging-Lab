"""
Advanced X25519 Key Exchange & Shared Secret Derivation Engine.
Provides ECDH key agreement and HKDF-SHA256 for domain-separated application key derivations.
"""

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from typing import Tuple, Any

from .exceptions import CryptographicOperationError, InvalidInputError, KeySerializationError
from .encoding import text_to_bytes, bytes_to_b64, b64_to_bytes
from .randomness import generate_random_bytes


# =====================================================================
# X25519 KEY GENERATION & VALIDATION
# =====================================================================

def generate_x25519_private_key() -> x25519.X25519PrivateKey:
    """Generates a secure X25519 private key."""
    return x25519.X25519PrivateKey.generate()


def derive_x25519_public_key(private_key: x25519.X25519PrivateKey) -> x25519.X25519PublicKey:
    """Derives the corresponding public key from an X25519 private key."""
    if not isinstance(private_key, x25519.X25519PrivateKey):
        raise InvalidInputError("Invalid private key type.")
    return private_key.public_key()


def generate_x25519_key_pair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """Generates an X25519 key pair strictly for Key Exchange."""
    priv = generate_x25519_private_key()
    return priv, derive_x25519_public_key(priv)


def validate_x25519_public_key(public_key: Any) -> None:
    """Strictly validates that the object is a valid X25519 Public Key."""
    if not isinstance(public_key, x25519.X25519PublicKey):
        raise InvalidInputError("Provided object is not a valid X25519PublicKey.")


def validate_x25519_key_pair(private_key: Any, public_key: Any) -> None:
    """Validates public and private key compatibility types."""
    if not isinstance(private_key, x25519.X25519PrivateKey):
        raise InvalidInputError("Invalid private key type.")
    validate_x25519_public_key(public_key)


# =====================================================================
# X25519 SERIALIZATION
# =====================================================================

def serialize_x25519_public_key(public_key: x25519.X25519PublicKey) -> str:
    """Serializes an X25519 public key to a Base64 DER string for exchange packages."""
    validate_x25519_public_key(public_key)
    try:
        der_bytes = public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return bytes_to_b64(der_bytes)
    except Exception as e:
        raise KeySerializationError(f"Failed to serialize X25519 public key: {str(e)}")


def deserialize_x25519_public_key(b64_key: str) -> x25519.X25519PublicKey:
    """Deserializes an X25519 public key from a Base64 DER string."""
    try:
        der_bytes = b64_to_bytes(b64_key)
        loaded_key = serialization.load_der_public_key(der_bytes)
        validate_x25519_public_key(loaded_key)
        return loaded_key
    except Exception as e:
        raise KeySerializationError(f"Failed to deserialize X25519 public key: {str(e)}")


# =====================================================================
# SHARED SECRET DERIVATION
# =====================================================================

def derive_x25519_shared_secret(private_key: x25519.X25519PrivateKey, peer_public_key: x25519.X25519PublicKey) -> bytes:
    """
    Derives the raw shared secret. 
    WARNING: MUST be passed through a KDF (like HKDF) before use. Never use raw ECDH output as an encryption key.
    """
    validate_x25519_key_pair(private_key, peer_public_key)
    try:
        return private_key.exchange(peer_public_key)
    except Exception as e:
        raise CryptographicOperationError(f"X25519 Key Exchange failed: {str(e)}")


def derive_shared_secret(private_key: x25519.X25519PrivateKey, peer_public_key: x25519.X25519PublicKey) -> bytes:
    """Alias preserving backward compatibility with M11 tests."""
    return derive_x25519_shared_secret(private_key, peer_public_key)


# =====================================================================
# HKDF-SHA256 KEY DERIVATION ENGINE
# =====================================================================

def generate_hkdf_salt(length: int = 16) -> bytes:
    """Generates a cryptographically secure random salt for HKDF extraction."""
    return generate_random_bytes(length)


def validate_derived_key(key: bytes, expected_length: int = 32) -> None:
    """Ensures the generated key perfectly matches expected byte constraints."""
    if not isinstance(key, bytes) or len(key) != expected_length:
        raise CryptographicOperationError(f"Derived key validation failed. Expected {expected_length} bytes, got {len(key) if isinstance(key, bytes) else 'invalid type'}.")


def derive_hkdf_key(shared_secret: bytes, salt: bytes, context_info: str, length: int = 32) -> bytes:
    """Passes the raw shared secret through HKDF-SHA256 to generate a strong symmetric key."""
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=salt,
            info=text_to_bytes(context_info)
        )
        derived_key = hkdf.derive(shared_secret)
        validate_derived_key(derived_key, length)
        return derived_key
    except Exception as e:
        raise CryptographicOperationError(f"HKDF derivation failed: {str(e)}")


def derive_encryption_key(shared_secret: bytes, salt: bytes, context: str) -> bytes:
    """Derives a domain-separated AES-256-GCM encryption key."""
    return derive_hkdf_key(shared_secret, salt, f"ENCRYPTION:{context}", 32)


def derive_authentication_key(shared_secret: bytes, salt: bytes, context: str) -> bytes:
    """Derives a domain-separated Authentication key (e.g., for HMAC)."""
    return derive_hkdf_key(shared_secret, salt, f"AUTHENTICATION:{context}", 32)


def derive_application_key(shared_secret: bytes, salt: bytes, context: str, label: str) -> bytes:
    """Derives a custom domain-separated application key."""
    return derive_hkdf_key(shared_secret, salt, f"APP_{label}:{context}", 32)
