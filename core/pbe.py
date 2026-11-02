"""
Advanced Password-Based Encryption (PBE) Engine.
Derives a 256-bit AES-GCM key from a user password using PBKDF2-HMAC-SHA256.
Enforces authenticated encryption, structured KDF metadata, and strict AAD binding.
"""

import json
from typing import Dict, Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .randomness import generate_random_bytes
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes

PBE_KEY_SIZE = 32         # 256 bits for AES-GCM
PBE_NONCE_SIZE = 12       # 96 bits for AES-GCM
PBE_SALT_SIZE = 16        # 128 bits minimum recommended for PBKDF2
PBE_DEFAULT_ITERATIONS = 600_000  # OWASP recommended baseline for PBKDF2-HMAC-SHA256 (2023)
PBE_MAX_ITERATIONS = 5_000_000    # Upper bound to prevent DoS via excessive derivation requests

def generate_pbe_salt() -> bytes:
    """Generates a cryptographically secure random 16-byte salt."""
    return generate_random_bytes(PBE_SALT_SIZE)

def validate_kdf_parameters(salt: bytes, iterations: int) -> None:
    """Validates KDF parameters against safe bounds to prevent DoS or weak derivation."""
    if len(salt) < PBE_SALT_SIZE:
        raise InvalidInputError(f"Salt must be at least {PBE_SALT_SIZE} bytes.")
    if not isinstance(iterations, int) or iterations < 10_000:
        raise InvalidInputError("Iteration count is dangerously low. Must be at least 10,000.")
    if iterations > PBE_MAX_ITERATIONS:
        raise InvalidInputError(f"Iteration count exceeds safety limits ({PBE_MAX_ITERATIONS}) to prevent resource exhaustion.")

def derive_encryption_key(password: str, salt: bytes, iterations: int) -> bytes:
    """
    Derives a 256-bit AES encryption key using PBKDF2-HMAC-SHA256.
    """
    if not password:
        raise InvalidInputError("Password cannot be empty.")
        
    validate_kdf_parameters(salt, iterations)
    
    try:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=PBE_KEY_SIZE,
            salt=salt,
            iterations=iterations,
        )
        return kdf.derive(text_to_bytes(password))
    except Exception as e:
        raise CryptographicOperationError(f"PBKDF2 Key Derivation failed: {str(e)}")

def _build_pbe_aad(version: str, kdf_algo: str, iterations: int, salt_b64: str, cipher_algo: str, nonce_b64: str, user_aad: str) -> bytes:
    """
    Constructs deterministic Additional Authenticated Data (AAD) mathematically binding 
    the plaintext to its exact KDF parameters, preventing metadata tampering.
    """
    aad_string = f"{version}|{kdf_algo}|{iterations}|{salt_b64}|{cipher_algo}|{nonce_b64}|{user_aad}"
    return text_to_bytes(aad_string)

def encrypt_with_password(password: str, plaintext: str, iterations: int = PBE_DEFAULT_ITERATIONS, user_aad: str = "") -> Dict[str, Any]:
    """
    Executes the complete PBE workflow: Derives key, encrypts via AES-GCM, and builds the versioned JSON package.
    """
    try:
        salt = generate_pbe_salt()
        nonce = generate_random_bytes(PBE_NONCE_SIZE)
        
        salt_b64 = bytes_to_b64(salt)
        nonce_b64 = bytes_to_b64(nonce)
        
        # 1. Derive Key
        dek = derive_encryption_key(password, salt, iterations)
        
        # 2. Build AAD combining structured package metadata and user AAD
        version = "1.0"
        aad_bytes = _build_pbe_aad(version, "PBKDF2", iterations, salt_b64, "AES-256-GCM", nonce_b64, user_aad)
        
        # 3. Encrypt & Authenticate via AES-256-GCM
        aesgcm = AESGCM(dek)
        pt_bytes = text_to_bytes(plaintext)
        ciphertext_with_tag = aesgcm.encrypt(nonce, pt_bytes, aad_bytes)
        
        # 4. Construct JSON Package
        return {
            "format_version": version,
            "encryption_type": "Password-Based Encryption",
            "kdf": {
                "algorithm": "PBKDF2",
                "prf": "HMAC-SHA256",
                "iterations": iterations,
                "salt": salt_b64
            },
            "cipher": {
                "algorithm": "AES-256-GCM",
                "nonce": nonce_b64
            },
            "aad": bytes_to_b64(text_to_bytes(user_aad)) if user_aad else "",
            "ciphertext": bytes_to_b64(ciphertext_with_tag)
        }
    except InvalidInputError:
        raise
    except Exception as e:
        raise CryptographicOperationError(f"Password Encryption failed: {str(e)}")

def decrypt_with_password(password: str, payload_json: str) -> str:
    """
    Authenticates and decrypts a PBE JSON package using the provided password.
    Rejects modified ciphertext, altered metadata, or incorrect passwords safely.
    """
    try:
        payload = json.loads(payload_json)
        
        version = payload.get("format_version")
        if version != "1.0":
            raise InvalidInputError(f"Unsupported format version: {version}")
            
        enc_type = payload.get("encryption_type")
        if enc_type != "Password-Based Encryption":
            raise InvalidInputError("Unsupported encryption type.")
            
        kdf = payload.get("kdf", {})
        cipher = payload.get("cipher", {})
        
        if kdf.get("algorithm") != "PBKDF2" or kdf.get("prf") != "HMAC-SHA256":
            raise InvalidInputError("Unsupported KDF algorithm/PRF.")
        if cipher.get("algorithm") != "AES-256-GCM":
            raise InvalidInputError("Unsupported Cipher algorithm.")
            
        iterations = kdf.get("iterations")
        salt_b64 = kdf.get("salt")
        nonce_b64 = cipher.get("nonce")
        user_aad_b64 = payload.get("aad", "")
        ct_b64 = payload.get("ciphertext")
        
        if not all([iterations, salt_b64, nonce_b64, ct_b64]):
            raise InvalidInputError("Malformed PBE Package: Missing required fields.")
            
        salt = b64_to_bytes(salt_b64)
        nonce = b64_to_bytes(nonce_b64)
        ciphertext_with_tag = b64_to_bytes(ct_b64)
        user_aad = bytes_to_text(b64_to_bytes(user_aad_b64)) if user_aad_b64 else ""
        
        if len(nonce) != PBE_NONCE_SIZE:
            raise InvalidInputError("Invalid AES-GCM nonce length.")
            
        # 1. Derive Key
        dek = derive_encryption_key(password, salt, iterations)
        
        # 2. Reconstruct AAD
        aad_bytes = _build_pbe_aad(version, "PBKDF2", iterations, salt_b64, "AES-256-GCM", nonce_b64, user_aad)
        
        # 3. Authenticate and Decrypt
        aesgcm = AESGCM(dek)
        try:
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, aad_bytes)
            return bytes_to_text(plaintext_bytes)
        except InvalidTag:
            raise AuthenticationError("Authentication failed. Incorrect password, or the package was tampered with.")
            
    except json.JSONDecodeError:
        raise InvalidInputError("Payload is not valid JSON.")
    except (AuthenticationError, CryptographicOperationError, InvalidInputError):
        raise
    except Exception as e:
        raise CryptographicOperationError(f"Password Decryption engine failed: {str(e)}")
