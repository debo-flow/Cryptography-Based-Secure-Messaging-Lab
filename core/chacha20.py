"""
Advanced ChaCha20 Stream Cipher Engine.
Implements raw ChaCha20 encryption and decryption.
CRITICAL WARNING: Raw ChaCha20 provides NO authentication or integrity checking.
Ciphertext modification will not raise errors during decryption.
"""

import json
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
from .exceptions import CryptographicOperationError, InvalidInputError
from .randomness import generate_random_bytes
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes

CHACHA20_KEY_SIZE = 32   # 256 bits
CHACHA20_NONCE_SIZE = 16 # 128 bits (required by Python cryptography library's raw ChaCha20)

def generate_chacha20_key() -> bytes:
    """Generates a secure 256-bit key for ChaCha20."""
    return generate_random_bytes(CHACHA20_KEY_SIZE)

def generate_chacha20_nonce() -> bytes:
    """Generates a secure 16-byte nonce for ChaCha20."""
    return generate_random_bytes(CHACHA20_NONCE_SIZE)

def validate_chacha20_key(key: bytes) -> None:
    if len(key) != CHACHA20_KEY_SIZE:
        raise InvalidInputError(f"ChaCha20 key must be exactly {CHACHA20_KEY_SIZE} bytes (256 bits). Provided: {len(key)} bytes.")

def validate_chacha20_nonce(nonce: bytes) -> None:
    if len(nonce) != CHACHA20_NONCE_SIZE:
        raise InvalidInputError(f"ChaCha20 nonce must be exactly {CHACHA20_NONCE_SIZE} bytes. Provided: {len(nonce)} bytes.")

def encrypt_chacha20(key: bytes, plaintext: str) -> Dict[str, Any]:
    """
    Encrypts a plaintext string using the ChaCha20 stream cipher.
    Returns a structured dictionary representing the JSON payload.
    """
    validate_chacha20_key(key)
    
    try:
        nonce = generate_chacha20_nonce()
        pt_bytes = text_to_bytes(plaintext)
        
        # Stream ciphers do not use a block mode (like CBC or GCM)
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None)
        encryptor = cipher.encryptor()
        
        ciphertext = encryptor.update(pt_bytes) + encryptor.finalize()
        
        return {
            "format_version": "1.0",
            "algorithm": "ChaCha20",
            "key_size": CHACHA20_KEY_SIZE * 8,
            "nonce": bytes_to_b64(nonce),
            "ciphertext": bytes_to_b64(ciphertext),
            "encoding": "UTF-8"
        }
    except Exception as e:
        raise CryptographicOperationError(f"ChaCha20 Encryption failed: {str(e)}")

def decrypt_chacha20(key: bytes, payload_json: str) -> str:
    """
    Decrypts a structured ChaCha20 JSON payload.
    WARNING: Does NOT verify authenticity. Will happily decrypt tampered ciphertext into garbage.
    """
    validate_chacha20_key(key)
    
    try:
        payload = json.loads(payload_json)
        
        if payload.get("format_version") != "1.0":
            raise InvalidInputError("Unsupported payload version. Expected '1.0'.")
            
        if payload.get("algorithm") != "ChaCha20":
            raise InvalidInputError(f"Unsupported algorithm: {payload.get('algorithm')}")
            
        b64_nonce = payload.get("nonce")
        b64_ct = payload.get("ciphertext")
        
        if not b64_nonce or not b64_ct:
            raise InvalidInputError("Malformed payload: Missing nonce or ciphertext.")
            
        nonce = b64_to_bytes(b64_nonce)
        ciphertext = b64_to_bytes(b64_ct)
        
        validate_chacha20_nonce(nonce)
        
        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None)
        decryptor = cipher.decryptor()
        
        # Because it's a stream cipher, decryption is just re-generating the keystream and XORing it
        plaintext_bytes = decryptor.update(ciphertext) + decryptor.finalize()
        
        return bytes_to_text(plaintext_bytes)
        
    except json.JSONDecodeError:
        raise InvalidInputError("Payload is not valid JSON.")
    except UnicodeDecodeError:
        # If the ciphertext was maliciously modified, the resulting XOR stream will produce 
        # invalid UTF-8 byte sequences, triggering this safely.
        raise CryptographicOperationError("Decryption resulted in invalid UTF-8 data. The ciphertext was likely tampered with or the wrong key was used.")
    except InvalidInputError:
        raise
    except Exception as e:
        raise CryptographicOperationError(f"ChaCha20 Decryption failed: {str(e)}")
