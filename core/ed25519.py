"""
Ed25519 Digital Signature Engine.
Provides modern, high-speed Edwards-curve Digital Signature Algorithm implementations.
Strictly for authenticity and integrity, not encryption.
"""
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature
from typing import Tuple
from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .encoding import text_to_bytes, b64_to_bytes, bytes_to_b64

def generate_ed25519_key_pair() -> Tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generates an Ed25519 key pair strictly for Digital Signatures."""
    private_key = ed25519.Ed25519PrivateKey.generate()
    return private_key, private_key.public_key()

def sign_message(private_key: ed25519.Ed25519PrivateKey, message: str) -> str:
    """Signs a message using Ed25519. Returns Base64 encoded signature."""
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise InvalidInputError("Invalid key type. Expected Ed25519PrivateKey.")
    try:
        msg_bytes = text_to_bytes(message)
        signature = private_key.sign(msg_bytes)
        return bytes_to_b64(signature)
    except Exception as e:
        raise CryptographicOperationError(f"Ed25519 Signing failed: {str(e)}")

def verify_signature(public_key: ed25519.Ed25519PublicKey, signature_b64: str, message: str) -> bool:
    """Verifies an Ed25519 signature against a specific message. Raises AuthenticationError on failure."""
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        raise InvalidInputError("Invalid key type. Expected Ed25519PublicKey.")
    try:
        msg_bytes = text_to_bytes(message)
        sig_bytes = b64_to_bytes(signature_b64)
        public_key.verify(sig_bytes, msg_bytes)
        return True
    except InvalidSignature:
        raise AuthenticationError("Digital Signature Verification Failed: The message was altered or signed by a different key.")
    except Exception as e:
        raise CryptographicOperationError(f"Ed25519 Verification process failed: {str(e)}")
