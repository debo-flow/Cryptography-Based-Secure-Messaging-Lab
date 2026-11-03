"""
Advanced Secure File Encryption Engine (M21).
Provides AEAD File Encryption with strict size limits (50MB) to safely encrypt in-memory 
without implementing custom chunked encryption protocols.
Supports Password-Based (PBE) and Hybrid (RSA-KEM) architectures for files.
"""

import json
import uuid
import os
import re
from datetime import datetime, timezone
from typing import Dict, Any, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .randomness import generate_random_bytes
from .encoding import bytes_to_b64, b64_to_bytes, bytes_to_text, text_to_bytes
from .kdf_engine import derive_key, generate_kdf_salt, KDF_REGISTRY
from .rsa import generate_public_key_fingerprint
from .hybrid import generate_hybrid_data_key

MAX_FILE_SIZE = 50 * 1024 * 1024  # 50 MB safety limit for in-memory AEAD
FILE_NONCE_SIZE = 12

def sanitize_filename(filename: str) -> str:
    """Removes path traversal characters and ensures a safe filename string."""
    if not filename:
        return "unnamed_file.bin"
    basename = os.path.basename(filename)
    safe_name = re.sub(r'[^a-zA-Z0-9_.-]', '_', basename)
    return safe_name if safe_name else "unnamed_file.bin"

def _build_file_aad(version: str, enc_type: str, filename: str, file_size: int, cipher_algo: str, nonce_b64: str) -> bytes:
    """Deterministically binds file metadata into the AEAD tag."""
    aad_str = f"{version}|{enc_type}|{filename}|{file_size}|{cipher_algo}|{nonce_b64}"
    return text_to_bytes(aad_str)

# === PBE FILE ENCRYPTION ===

def encrypt_file_pbe(password: str, file_data: bytes, original_filename: str, kdf_algo: str = "Argon2id", kdf_params: dict = None) -> Dict[str, Any]:
    """Encrypts a file using PBKDF2/Scrypt/Argon2id derived keys and AEAD."""
    if len(file_data) > MAX_FILE_SIZE:
        raise InvalidInputError(f"File exceeds maximum safe in-memory limit of {MAX_FILE_SIZE // (1024*1024)} MB.")
    if not password:
        raise InvalidInputError("Password cannot be empty.")
        
    if not kdf_params:
        if kdf_algo not in KDF_REGISTRY:
            raise InvalidInputError("Unsupported KDF algorithm.")
        kdf_params = KDF_REGISTRY[kdf_algo]["defaults"]

    try:
        safe_filename = sanitize_filename(original_filename)
        salt = generate_kdf_salt()
        nonce = generate_random_bytes(FILE_NONCE_SIZE)
        
        salt_b64 = bytes_to_b64(salt)
        nonce_b64 = bytes_to_b64(nonce)
        
        dek = derive_key(password, salt, kdf_algo, kdf_params)
        
        version = "1.0"
        enc_type = "PBE-File"
        cipher_algo = "AES-256-GCM"
        
        aad_bytes = _build_file_aad(version, enc_type, safe_filename, len(file_data), cipher_algo, nonce_b64)
        
        aesgcm = AESGCM(dek)
        ciphertext_with_tag = aesgcm.encrypt(nonce, file_data, aad_bytes)
        
        return {
            "format_version": version,
            "encryption_type": enc_type,
            "original_filename": safe_filename,
            "file_size": len(file_data),
            "kdf": {
                "algorithm": kdf_algo,
                "parameters": kdf_params,
                "salt": salt_b64
            },
            "cipher": {
                "algorithm": cipher_algo,
                "nonce": nonce_b64
            },
            "ciphertext": bytes_to_b64(ciphertext_with_tag),
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    except InvalidInputError:
        raise
    except Exception as e:
        raise CryptographicOperationError(f"File Encryption failed: {str(e)}")

def decrypt_file_pbe(password: str, payload_json: str) -> Tuple[str, bytes]:
    """Decrypts a PBE file package, verifies integrity, and returns (filename, file_bytes)."""
    try:
        payload = json.loads(payload_json)
        
        version = payload.get("format_version")
        if version != "1.0": raise InvalidInputError("Unsupported format version.")
        if payload.get("encryption_type") != "PBE-File": raise InvalidInputError("Not a PBE File package.")
            
        filename = payload.get("original_filename", "unnamed.bin")
        file_size = payload.get("file_size", 0)
        
        kdf = payload.get("kdf", {})
        cipher = payload.get("cipher", {})
        
        kdf_algo = kdf.get("algorithm")
        kdf_params = kdf.get("parameters", {})
        salt_b64 = kdf.get("salt")
        
        cipher_algo = cipher.get("algorithm")
        nonce_b64 = cipher.get("nonce")
        ct_b64 = payload.get("ciphertext")
        
        if not all([kdf_algo, salt_b64, cipher_algo, nonce_b64, ct_b64]):
            raise InvalidInputError("Malformed File Package: Missing fields.")
            
        if cipher_algo != "AES-256-GCM":
            raise InvalidInputError(f"Unsupported cipher: {cipher_algo}")
            
        salt = b64_to_bytes(salt_b64)
        nonce = b64_to_bytes(nonce_b64)
        ciphertext_with_tag = b64_to_bytes(ct_b64)
        
        if len(nonce) != FILE_NONCE_SIZE: raise InvalidInputError("Invalid nonce length.")
        
        dek = derive_key(password, salt, kdf_algo, kdf_params)
        aad_bytes = _build_file_aad(version, "PBE-File", filename, file_size, cipher_algo, nonce_b64)
        
        aesgcm = AESGCM(dek)
        try:
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, aad_bytes)
            return filename, plaintext_bytes
        except InvalidTag:
            raise AuthenticationError("File Authentication failed. Incorrect password, or the file was tampered with.")
            
    except json.JSONDecodeError: raise InvalidInputError("Payload is not valid JSON.")
    except (AuthenticationError, CryptographicOperationError, InvalidInputError): raise
    except Exception as e: raise CryptographicOperationError(f"File Decryption failed: {str(e)}")

# === HYBRID FILE ENCRYPTION ===

def encrypt_file_hybrid(pub_key: rsa.RSAPublicKey, file_data: bytes, original_filename: str, cipher_algo: str = "AES-256-GCM") -> Dict[str, Any]:
    """Encrypts a file using a random DEK, then wraps the DEK using the recipient's RSA Public Key."""
    if len(file_data) > MAX_FILE_SIZE:
        raise InvalidInputError(f"File exceeds maximum safe in-memory limit of {MAX_FILE_SIZE // (1024*1024)} MB.")
    if cipher_algo not in ["AES-256-GCM", "ChaCha20-Poly1305"]:
        raise InvalidInputError("Unsupported cipher algorithm.")
        
    try:
        safe_filename = sanitize_filename(original_filename)
        dek = generate_hybrid_data_key()
        nonce = generate_random_bytes(FILE_NONCE_SIZE)
        nonce_b64 = bytes_to_b64(nonce)
        
        recipient_fp = generate_public_key_fingerprint(pub_key)
        version = "1.0"
        enc_type = "Hybrid-File"
        
        aad_bytes = _build_file_aad(version, enc_type, safe_filename, len(file_data), cipher_algo, nonce_b64)
        
        cipher = AESGCM(dek) if cipher_algo == "AES-256-GCM" else ChaCha20Poly1305(dek)
        ciphertext_with_tag = cipher.encrypt(nonce, file_data, aad_bytes)
        
        wrapped_dek = pub_key.encrypt(
            dek,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        
        return {
            "format_version": version,
            "encryption_type": enc_type,
            "original_filename": safe_filename,
            "file_size": len(file_data),
            "key_wrapping": {
                "algorithm": "RSA-OAEP",
                "hash": "SHA-256",
                "recipient_key_fingerprint": recipient_fp,
                "wrapped_dek": bytes_to_b64(wrapped_dek)
            },
            "cipher": {
                "algorithm": cipher_algo,
                "nonce": nonce_b64
            },
            "ciphertext": bytes_to_b64(ciphertext_with_tag),
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise CryptographicOperationError(f"Hybrid File Encryption failed: {str(e)}")

def decrypt_file_hybrid(priv_key: rsa.RSAPrivateKey, payload_json: str) -> Tuple[str, bytes]:
    """Unwraps the DEK and decrypts the hybrid file package."""
    try:
        payload = json.loads(payload_json)
        
        version = payload.get("format_version")
        if version != "1.0": raise InvalidInputError("Unsupported format version.")
        if payload.get("encryption_type") != "Hybrid-File": raise InvalidInputError("Not a Hybrid File package.")
            
        filename = payload.get("original_filename", "unnamed.bin")
        file_size = payload.get("file_size", 0)
        
        kw = payload.get("key_wrapping", {})
        cipher = payload.get("cipher", {})
        
        cipher_algo = cipher.get("algorithm")
        nonce_b64 = cipher.get("nonce")
        ct_b64 = payload.get("ciphertext")
        wrapped_dek_b64 = kw.get("wrapped_dek")
        
        if not all([cipher_algo, nonce_b64, ct_b64, wrapped_dek_b64]):
            raise InvalidInputError("Malformed File Package: Missing fields.")
            
        nonce = b64_to_bytes(nonce_b64)
        ciphertext_with_tag = b64_to_bytes(ct_b64)
        wrapped_dek = b64_to_bytes(wrapped_dek_b64)
        
        try:
            dek = priv_key.decrypt(
                wrapped_dek,
                padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
            )
        except ValueError:
            raise CryptographicOperationError("DEK Unwrapping failed. Incorrect private key.")
            
        aad_bytes = _build_file_aad(version, "Hybrid-File", filename, file_size, cipher_algo, nonce_b64)
        
        cipher_engine = AESGCM(dek) if cipher_algo == "AES-256-GCM" else ChaCha20Poly1305(dek)
        try:
            plaintext_bytes = cipher_engine.decrypt(nonce, ciphertext_with_tag, aad_bytes)
            return filename, plaintext_bytes
        except InvalidTag:
            raise AuthenticationError("File Authentication failed. The file metadata or ciphertext was tampered with.")
            
    except json.JSONDecodeError: raise InvalidInputError("Payload is not valid JSON.")
    except (AuthenticationError, CryptographicOperationError, InvalidInputError): raise
    except Exception as e: raise CryptographicOperationError(f"Hybrid File Decryption failed: {str(e)}")
