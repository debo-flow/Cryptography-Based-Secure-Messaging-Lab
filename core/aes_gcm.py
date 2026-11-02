"""
Advanced AES-GCM Authenticated Encryption Engine.
Implements AES-128-GCM, AES-192-GCM, and AES-256-GCM.
Utilizes the high-level AEAD API from the Python cryptography library.
"""
import json
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .exceptions import CryptographicOperationError, AuthenticationError, InvalidInputError
from .randomness import generate_random_bytes
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes

AES_GCM_CONFIGS = {
    "AES-128-GCM": {"key_size": 16},
    "AES-192-GCM": {"key_size": 24},
    "AES-256-GCM": {"key_size": 32}
}

def encrypt_aes_gcm(key: bytes, plaintext: str, algorithm: str = "AES-256-GCM", aad: str = "") -> dict:
    """
    Encrypts and authenticates a plaintext string using AES-GCM.
    Produces a 96-bit (12-byte) nonce and includes a 128-bit authentication tag appended to the ciphertext.
    """
    if algorithm not in AES_GCM_CONFIGS:
        raise InvalidInputError(f"Unsupported algorithm: {algorithm}")
    
    key_size = AES_GCM_CONFIGS[algorithm]["key_size"]
    if len(key) != key_size:
        raise InvalidInputError(f"Key for {algorithm} must be exactly {key_size} bytes.")

    try:
        # Initialize GCM and strict 96-bit nonce
        aesgcm = AESGCM(key)
        nonce = generate_random_bytes(12) 
        
        pt_bytes = text_to_bytes(plaintext)
        aad_bytes = text_to_bytes(aad) if aad else None
        
        # The encrypt function natively appends the 128-bit authentication tag to the ciphertext
        ciphertext_with_tag = aesgcm.encrypt(nonce, pt_bytes, aad_bytes)
        
        # Construct versioned JSON layout
        return {
            "version": 1,
            "algorithm": algorithm,
            "nonce": bytes_to_b64(nonce),
            "ciphertext": bytes_to_b64(ciphertext_with_tag),
            "aad": bytes_to_b64(aad_bytes) if aad_bytes else ""
        }
    except Exception as e:
        raise CryptographicOperationError(f"AES-GCM Encryption failed: {str(e)}")

def decrypt_aes_gcm(key: bytes, payload_json: str) -> str:
    """
    Verifies AES-GCM authentication over ciphertext and AAD, and returns plaintext if valid.
    Fails securely on tampering or wrong key.
    """
    try:
        payload = json.loads(payload_json)
        
        version = payload.get("version")
        algo_str = payload.get("algorithm")
        b64_nonce = payload.get("nonce")
        b64_ct = payload.get("ciphertext")
        b64_aad = payload.get("aad", "")
        
        if not all([version, algo_str, b64_nonce, b64_ct]):
            raise InvalidInputError("Malformed payload: Missing required fields.")
            
        if algo_str not in AES_GCM_CONFIGS:
            raise InvalidInputError(f"Unsupported algorithm identifier: {algo_str}")
            
        key_size = AES_GCM_CONFIGS[algo_str]["key_size"]
        if len(key) != key_size:
            raise InvalidInputError(f"Key must be {key_size} bytes for {algo_str}.")

        nonce = b64_to_bytes(b64_nonce)
        if len(nonce) != 12:
            raise InvalidInputError("Invalid nonce length for AES-GCM. Expected 12 bytes (96-bit).")
            
        ciphertext_with_tag = b64_to_bytes(b64_ct)
        aad_bytes = b64_to_bytes(b64_aad) if b64_aad else None
        
        aesgcm = AESGCM(key)
        
        try:
            # Decrypt verifies the tag natively before returning plaintext
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, aad_bytes)
            return bytes_to_text(plaintext_bytes)
            
        except InvalidTag:
            # Catching the specific cryptography exception and translating to our secure exception architecture
            raise AuthenticationError("Authentication failed. Message tampered, wrong key, or incorrect AAD.")
            
    except AuthenticationError:
        raise
    except json.JSONDecodeError:
        raise InvalidInputError("Payload is not valid JSON.")
    except Exception as e:
        raise CryptographicOperationError(f"AES-GCM Decryption failed: {str(e)}")
