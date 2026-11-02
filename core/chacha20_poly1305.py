"""
Advanced ChaCha20-Poly1305 Authenticated Encryption Engine.
Implements AEAD (Authenticated Encryption with Associated Data).
Provides confidentiality, integrity, and authenticity using a 256-bit key and 96-bit nonce.
"""

import json
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .randomness import generate_random_bytes
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes

CHACHA20_POLY1305_KEY_SIZE = 32  # 256 bits
CHACHA20_POLY1305_NONCE_SIZE = 12 # 96 bits

def generate_chacha20_poly1305_key() -> bytes:
    """Generates a secure 256-bit key for ChaCha20-Poly1305."""
    return generate_random_bytes(CHACHA20_POLY1305_KEY_SIZE)

def generate_chacha20_poly1305_nonce() -> bytes:
    """Generates a secure 96-byte nonce for ChaCha20-Poly1305."""
    return generate_random_bytes(CHACHA20_POLY1305_NONCE_SIZE)

def validate_chacha20_poly1305_key(key: bytes) -> None:
    """Validates the exact 256-bit key requirement."""
    if len(key) != CHACHA20_POLY1305_KEY_SIZE:
        raise InvalidInputError(f"ChaCha20-Poly1305 key must be {CHACHA20_POLY1305_KEY_SIZE} bytes. Provided: {len(key)}.")

def validate_chacha20_poly1305_nonce(nonce: bytes) -> None:
    """Validates the exact 96-bit nonce requirement."""
    if len(nonce) != CHACHA20_POLY1305_NONCE_SIZE:
        raise InvalidInputError(f"ChaCha20-Poly1305 nonce must be {CHACHA20_POLY1305_NONCE_SIZE} bytes. Provided: {len(nonce)}.")

def encrypt_chacha20_poly1305(key: bytes, plaintext: str, aad_str: str = "") -> Dict[str, Any]:
    """
    Encrypts and authenticates a plaintext string using ChaCha20-Poly1305.
    Returns a structured dictionary representing the versioned JSON payload.
    """
    validate_chacha20_poly1305_key(key)
    
    try:
        nonce = generate_chacha20_poly1305_nonce()
        pt_bytes = text_to_bytes(plaintext)
        aad_bytes = text_to_bytes(aad_str) if aad_str else None
        
        aead = ChaCha20Poly1305(key)
        
        # cryptography library appends the 128-bit Poly1305 MAC tag to the ciphertext automatically
        ciphertext_with_tag = aead.encrypt(nonce, pt_bytes, aad_bytes)
        
        return {
            "format_version": "1.0",
            "algorithm": "ChaCha20-Poly1305",
            "key_size": CHACHA20_POLY1305_KEY_SIZE * 8,
            "nonce": bytes_to_b64(nonce),
            "ciphertext": bytes_to_b64(ciphertext_with_tag),
            "aad": bytes_to_b64(aad_bytes) if aad_bytes else None,
            "encoding": "UTF-8"
        }
    except Exception as e:
        raise CryptographicOperationError(f"ChaCha20-Poly1305 Encryption failed: {str(e)}")

def decrypt_chacha20_poly1305(key: bytes, payload_json: str) -> str:
    """
    Authenticates and decrypts a ChaCha20-Poly1305 payload.
    Strictly prevents plaintext exposure if the authentication tag or AAD is invalid.
    """
    validate_chacha20_poly1305_key(key)
    
    try:
        payload = json.loads(payload_json)
        
        if payload.get("format_version") != "1.0":
            raise InvalidInputError("Unsupported payload version. Expected '1.0'.")
            
        if payload.get("algorithm") != "ChaCha20-Poly1305":
            raise InvalidInputError(f"Unsupported algorithm: {payload.get('algorithm')}")
            
        b64_nonce = payload.get("nonce")
        b64_ct = payload.get("ciphertext")
        b64_aad = payload.get("aad")
        
        if not b64_nonce or not b64_ct:
            raise InvalidInputError("Malformed payload: Missing nonce or ciphertext.")
            
        nonce = b64_to_bytes(b64_nonce)
        ciphertext_with_tag = b64_to_bytes(b64_ct)
        aad_bytes = b64_to_bytes(b64_aad) if b64_aad else None
        
        validate_chacha20_poly1305_nonce(nonce)
        
        aead = ChaCha20Poly1305(key)
        
        try:
            # Decrypt verifies the Poly1305 tag internally before returning any plaintext
            plaintext_bytes = aead.decrypt(nonce, ciphertext_with_tag, aad_bytes)
            return bytes_to_text(plaintext_bytes)
        except InvalidTag:
            raise AuthenticationError("Authentication failed. Message tampered, wrong key, or altered AAD.")
            
    except AuthenticationError:
        raise
    except json.JSONDecodeError:
        raise InvalidInputError("Payload is not valid JSON.")
    except Exception as e:
        raise CryptographicOperationError(f"ChaCha20-Poly1305 Decryption validation failed: {str(e)}")
