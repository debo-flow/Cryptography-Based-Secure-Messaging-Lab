"""
Advanced Password-Based Encryption (PBE) Engine.
Integrates PBKDF2, Scrypt, and Argon2id via the new KDF Engine.
Uses AES-256-GCM for Authenticated Encryption.
Fully backwards-compatible with M13 (v1.0) JSON packages.
"""
import json
from typing import Dict, Any
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .randomness import generate_random_bytes
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes
from .kdf_engine import derive_key, generate_kdf_salt, KDF_REGISTRY

PBE_NONCE_SIZE = 12 # 96 bits for AES-GCM

def _build_pbe_aad(version: str, kdf_algo: str, kdf_params: dict, salt_b64: str, cipher_algo: str, nonce_b64: str, user_aad: str) -> bytes:
    """
    Constructs deterministic Additional Authenticated Data (AAD).
    Handles M13 legacy fallback (v1.0) strictly, while supporting generic param dictionaries in v1.1.
    """
    if version == "1.0":
        # M13 Hardcoded compatibility string
        iters = kdf_params.get("iterations", 600000)
        aad_string = f"{version}|PBKDF2|{iters}|{salt_b64}|{cipher_algo}|{nonce_b64}|{user_aad}"
    elif version == "1.1":
        # M14 flexible param dictionary parsing (sorted for deterministic ordering)
        sorted_params = ",".join(f"{k}={v}" for k, v in sorted(kdf_params.items()))
        aad_string = f"{version}|{kdf_algo}|{sorted_params}|{salt_b64}|{cipher_algo}|{nonce_b64}|{user_aad}"
    else:
        raise InvalidInputError(f"Unsupported package version for AAD: {version}")
        
    return text_to_bytes(aad_string)

def encrypt_with_password(password: str, plaintext: str, kdf_algo: str = "Argon2id", kdf_params: dict = None, user_aad: str = "") -> Dict[str, Any]:
    """
    Executes the complete PBE workflow using any supported KDF, securing plaintext via AES-GCM.
    Outputs format_version 1.1 JSON payload.
    """
    if not kdf_params:
        if kdf_algo not in KDF_REGISTRY:
            raise InvalidInputError("Unsupported KDF algorithm.")
        kdf_params = KDF_REGISTRY[kdf_algo]["defaults"]
        
    try:
        salt = generate_kdf_salt()
        nonce = generate_random_bytes(PBE_NONCE_SIZE)
        
        salt_b64 = bytes_to_b64(salt)
        nonce_b64 = bytes_to_b64(nonce)
        
        # 1. Derive Key using the Unified Engine
        dek = derive_key(password, salt, kdf_algo, kdf_params)
        
        # 2. Build AAD
        version = "1.1"
        aad_bytes = _build_pbe_aad(version, kdf_algo, kdf_params, salt_b64, "AES-256-GCM", nonce_b64, user_aad)
        
        # 3. Encrypt & Authenticate via AES-256-GCM
        aesgcm = AESGCM(dek)
        pt_bytes = text_to_bytes(plaintext)
        ciphertext_with_tag = aesgcm.encrypt(nonce, pt_bytes, aad_bytes)
        
        # 4. Construct JSON Package
        return {
            "format_version": version,
            "encryption_type": "Password-Based Encryption",
            "kdf": {
                "algorithm": kdf_algo,
                "parameters": kdf_params,
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
    Authenticates and decrypts a PBE JSON package (Supports v1.0 and v1.1).
    """
    try:
        payload = json.loads(payload_json)
        
        version = payload.get("format_version")
        if version not in ["1.0", "1.1"]:
            raise InvalidInputError(f"Unsupported format version: {version}")
            
        enc_type = payload.get("encryption_type")
        if enc_type != "Password-Based Encryption":
            raise InvalidInputError("Unsupported encryption type.")
            
        kdf = payload.get("kdf", {})
        cipher = payload.get("cipher", {})
        
        if cipher.get("algorithm") != "AES-256-GCM":
            raise InvalidInputError("Unsupported Cipher algorithm.")
            
        # Parse KDF metadata depending on version
        if version == "1.0":
            kdf_algo = "PBKDF2-HMAC-SHA256"
            kdf_params = {"iterations": kdf.get("iterations")}
            if not kdf_params["iterations"]: raise InvalidInputError("Missing iterations in v1.0 package.")
        else:
            kdf_algo = kdf.get("algorithm")
            kdf_params = kdf.get("parameters", {})
            
        salt_b64 = kdf.get("salt")
        nonce_b64 = cipher.get("nonce")
        user_aad_b64 = payload.get("aad", "")
        ct_b64 = payload.get("ciphertext")
        
        if not all([salt_b64, nonce_b64, ct_b64]):
            raise InvalidInputError("Malformed PBE Package: Missing required fields.")
            
        salt = b64_to_bytes(salt_b64)
        nonce = b64_to_bytes(nonce_b64)
        ciphertext_with_tag = b64_to_bytes(ct_b64)
        user_aad = bytes_to_text(b64_to_bytes(user_aad_b64)) if user_aad_b64 else ""
        
        if len(nonce) != PBE_NONCE_SIZE:
            raise InvalidInputError("Invalid AES-GCM nonce length.")
            
        # 1. Derive Key
        dek = derive_key(password, salt, kdf_algo, kdf_params)
        
        # 2. Reconstruct AAD
        aad_bytes = _build_pbe_aad(version, kdf_algo, kdf_params, salt_b64, "AES-256-GCM", nonce_b64, user_aad)
        
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

def migrate_pbe_package(password: str, payload_json: str, new_kdf_algo: str, new_kdf_params: dict = None) -> Dict[str, Any]:
    """
    Migration System: Safely decrypts an old package (e.g. v1.0 PBKDF2) and re-encrypts it to a new KDF (e.g. v1.1 Argon2id).
    Fails safely if password or original package is invalid.
    """
    # 1. Authenticate and Decrypt strictly
    plaintext = decrypt_with_password(password, payload_json)
    
    # Extract existing user AAD if present to preserve it
    payload = json.loads(payload_json)
    user_aad_b64 = payload.get("aad", "")
    user_aad = bytes_to_text(b64_to_bytes(user_aad_b64)) if user_aad_b64 else ""
    
    # 2. Re-encrypt with new KDF
    return encrypt_with_password(password, plaintext, new_kdf_algo, new_kdf_params, user_aad)
