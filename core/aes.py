"""
Advanced AES Encryption Engine.
Implements AES-128, AES-192, and AES-256 in CBC mode with PKCS7 padding.
Strictly enforces Encrypt-then-MAC using HMAC-SHA256.
Independent keys are derived safely using HKDF.
"""

import json
from typing import Dict, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature

from .exceptions import CryptographicOperationError, AuthenticationError, InvalidInputError
from .randomness import generate_random_bytes
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes

# Supported configurations
AES_CONFIGS = {
    "AES-128": {"key_size": 16},
    "AES-192": {"key_size": 24},
    "AES-256": {"key_size": 32}
}

def derive_keys(master_key: bytes, enc_key_size: int) -> Tuple[bytes, bytes]:
    """
    Uses HKDF to securely derive two mathematically independent keys from one master key.
    Returns: (Encryption Key, MAC Key)
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=enc_key_size + 32, # enc_key_size for AES + 32 bytes for HMAC-SHA256
        salt=None,                # Deterministic derivation from master key for simplicity in this lab
        info=b"AES-CBC-HMAC-SHA256-V1"
    )
    key_material = hkdf.derive(master_key)
    return key_material[:enc_key_size], key_material[enc_key_size:]

def encrypt_aes(master_key: bytes, plaintext: str, algorithm: str = "AES-256") -> Dict[str, str]:
    """
    Encrypts a plaintext string using the specified AES algorithm and Encrypt-then-MAC.
    """
    if algorithm not in AES_CONFIGS:
        raise InvalidInputError(f"Unsupported algorithm: {algorithm}")
    
    enc_key_size = AES_CONFIGS[algorithm]["key_size"]
    
    if len(master_key) != enc_key_size:
        raise InvalidInputError(f"Master key for {algorithm} must be exactly {enc_key_size} bytes.")

    try:
        # 1. Derive independent keys
        enc_key, mac_key = derive_keys(master_key, enc_key_size)
        
        # 2. Pad plaintext (PKCS7)
        raw_bytes = text_to_bytes(plaintext)
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(raw_bytes) + padder.finalize()
        
        # 3. Generate secure unpredictable IV
        iv = generate_random_bytes(16)
        
        # 4. Encrypt (CBC Mode)
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        # 5. Authenticate (Encrypt-then-MAC) covering IV + Ciphertext
        h = hmac.HMAC(mac_key, hashes.SHA256())
        h.update(iv + ciphertext)
        mac_tag = h.finalize()
        
        # 6. Construct structured JSON payload
        return {
            "version": 1,
            "algorithm": f"{algorithm}-CBC-HMAC-SHA256",
            "iv": bytes_to_b64(iv),
            "ciphertext": bytes_to_b64(ciphertext),
            "authentication_tag": bytes_to_b64(mac_tag)
        }
    except Exception as e:
        raise CryptographicOperationError(f"Encryption failed: {str(e)}")

def decrypt_aes(master_key: bytes, payload_json: str) -> str:
    """
    Verifies authentication tag, then decrypts the AES payload.
    """
    try:
        payload = json.loads(payload_json)
        
        version = payload.get("version")
        algo_str = payload.get("algorithm", "")
        b64_iv = payload.get("iv")
        b64_ct = payload.get("ciphertext")
        b64_mac = payload.get("authentication_tag")
        
        if not all([version, algo_str, b64_iv, b64_ct, b64_mac]):
            raise InvalidInputError("Malformed payload: Missing required fields.")
            
        base_algo = algo_str.split("-CBC")[0]
        if base_algo not in AES_CONFIGS:
            raise InvalidInputError(f"Unsupported or tampered algorithm identifier: {base_algo}")

        enc_key_size = AES_CONFIGS[base_algo]["key_size"]
        if len(master_key) != enc_key_size:
             raise InvalidInputError(f"Master key must be {enc_key_size} bytes for {base_algo}.")

        iv = b64_to_bytes(b64_iv)
        ciphertext = b64_to_bytes(b64_ct)
        mac_tag = b64_to_bytes(b64_mac)
        
        # 1. Derive identical independent keys
        enc_key, mac_key = derive_keys(master_key, enc_key_size)
        
        # 2. Authenticate FIRST (Constant-time comparison via HMAC verification)
        h = hmac.HMAC(mac_key, hashes.SHA256())
        h.update(iv + ciphertext)
        try:
            h.verify(mac_tag)
        except InvalidSignature:
            # Raise generic error without leaking whether padding or MAC failed
            raise AuthenticationError("Authentication failed. Ciphertext tampered or wrong key.")
            
        # 3. Decrypt
        cipher = Cipher(algorithms.AES(enc_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_data = decryptor.update(ciphertext) + decryptor.finalize()
        
        # 4. Unpad
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        raw_bytes = unpadder.update(padded_data) + unpadder.finalize()
        
        return bytes_to_text(raw_bytes)
        
    except AuthenticationError:
        raise
    except json.JSONDecodeError:
        raise InvalidInputError("Payload is not valid JSON.")
    except Exception as e:
        # Catch padding errors or other structural issues securely
        raise CryptographicOperationError(f"Decryption failed: {str(e)}")
