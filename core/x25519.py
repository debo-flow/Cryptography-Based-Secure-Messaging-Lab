"""
X25519 Key Exchange Engine.
Provides modern, high-speed, and secure elliptic curve Diffie-Hellman key agreement.
"""
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from typing import Tuple
from .exceptions import CryptographicOperationError, InvalidInputError
from .encoding import text_to_bytes

def generate_x25519_key_pair() -> Tuple[x25519.X25519PrivateKey, x25519.X25519PublicKey]:
    """Generates an X25519 key pair strictly for Key Exchange."""
    private_key = x25519.X25519PrivateKey.generate()
    return private_key, private_key.public_key()

def derive_shared_secret(private_key: x25519.X25519PrivateKey, peer_public_key: x25519.X25519PublicKey) -> bytes:
    """Derives the raw shared secret. MUST be passed through a KDF before use."""
    if not isinstance(private_key, x25519.X25519PrivateKey) or not isinstance(peer_public_key, x25519.X25519PublicKey):
        raise InvalidInputError("Invalid key types for X25519 shared secret derivation.")
    try:
        return private_key.exchange(peer_public_key)
    except Exception as e:
        raise CryptographicOperationError(f"X25519 Key Exchange failed: {str(e)}")

def derive_hkdf_key(shared_secret: bytes, context_info: str = "X25519-Exchange", length: int = 32) -> bytes:
    """Passes the raw shared secret through HKDF-SHA256 to generate a cryptographically strong symmetric key."""
    try:
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=text_to_bytes(context_info)
        )
        return hkdf.derive(shared_secret)
    except Exception as e:
        raise CryptographicOperationError(f"HKDF derivation failed: {str(e)}")
