"""
Advanced Cryptographic Key Management Engine (KME) - Milestone 22.
Provides centralized lifecycle management, secure storage at rest (using Argon2id+AES-GCM), 
auditing, rotation, and revocation for all cryptographic keys.
"""
import json
import uuid
import time
from enum import Enum
from datetime import datetime, timezone
from typing import Dict, Any, Tuple, Optional, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .randomness import generate_random_bytes
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes
from .kdf_engine import derive_key, generate_kdf_salt
from .rsa import generate_rsa_key_pair, generate_public_key_fingerprint
from .ecc import generate_ecc_key_pair
from .x25519 import generate_x25519_key_pair
from .ed25519 import generate_ed25519_key_pair
from .hmac_engine import generate_hmac_key
from .public_key_manager import get_public_key_fingerprint

class KeyStatus(Enum):
    GENERATED = "GENERATED"
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    EXPIRED = "EXPIRED"
    ROTATED = "ROTATED"
    REVOKED = "REVOKED"
    COMPROMISED = "COMPROMISED"
    ARCHIVED = "ARCHIVED"

class KeyCategory(Enum):
    SYMMETRIC = "SYMMETRIC"
    ASYMMETRIC_PUBLIC = "ASYMMETRIC_PUBLIC"
    ASYMMETRIC_PRIVATE = "ASYMMETRIC_PRIVATE"

KME_NONCE_SIZE = 12

def generate_managed_key(algorithm: str, key_size_or_curve: Any, usage: str, identity: str = "System") -> Tuple[str, Any, Dict[str, Any]]:
    """
    Generates a cryptographic key, assigns a unique ID, and creates unclassified metadata.
    Returns: (key_id, raw_key_object, metadata_dict)
    """
    key_id = str(uuid.uuid4())
    created_at = time.time()
    
    if algorithm.startswith("AES") or algorithm.startswith("ChaCha20") or algorithm.startswith("HMAC"):
        category = KeyCategory.SYMMETRIC.value
        if isinstance(key_size_or_curve, int):
            raw_key = generate_random_bytes(key_size_or_curve // 8)
        else:
            raw_key = generate_random_bytes(32)
        fingerprint = None
    elif "RSA" in algorithm:
        category = KeyCategory.ASYMMETRIC_PRIVATE.value
        raw_key, pub = generate_rsa_key_pair(int(key_size_or_curve))
        fingerprint = generate_public_key_fingerprint(pub)
    elif "ECDSA" in algorithm:
        category = KeyCategory.ASYMMETRIC_PRIVATE.value
        raw_key, pub = generate_ecc_key_pair(str(key_size_or_curve))
        fingerprint = get_public_key_fingerprint(pub)
    elif "Ed25519" in algorithm:
        category = KeyCategory.ASYMMETRIC_PRIVATE.value
        raw_key, pub = generate_ed25519_key_pair()
        fingerprint = get_public_key_fingerprint(pub)
    elif "X25519" in algorithm:
        category = KeyCategory.ASYMMETRIC_PRIVATE.value
        raw_key, pub = generate_x25519_key_pair()
        fingerprint = get_public_key_fingerprint(pub)
    else:
        raise InvalidInputError(f"Unsupported algorithm for KME generation: {algorithm}")
        
    meta = {
        "key_id": key_id,
        "category": category,
        "algorithm": algorithm,
        "fingerprint": fingerprint,
        "status": KeyStatus.GENERATED.value,
        "intended_usage": usage,
        "associated_identity": identity,
        "created_at": created_at,
        "expires_at": None,
        "rotated_to": None,
        "revoked_at": None,
        "revocation_reason": None
    }
    
    return key_id, raw_key, meta

def _serialize_for_storage(raw_key: Any, category: str) -> bytes:
    """Extracts raw bytes or unencrypted PKCS8 DER for local storage (KME handles the encryption wrapper)."""
    if category == KeyCategory.SYMMETRIC.value:
        return raw_key
    elif category == KeyCategory.ASYMMETRIC_PRIVATE.value:
        return raw_key.private_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
    elif category == KeyCategory.ASYMMETRIC_PUBLIC.value:
        return raw_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    raise InvalidInputError("Unknown key category.")

def _deserialize_from_storage(key_bytes: bytes, algorithm: str, category: str) -> Any:
    """Restores the cryptographic object from stored bytes."""
    if category == KeyCategory.SYMMETRIC.value:
        return key_bytes
    elif category == KeyCategory.ASYMMETRIC_PRIVATE.value:
        return serialization.load_der_private_key(key_bytes, password=None)
    elif category == KeyCategory.ASYMMETRIC_PUBLIC.value:
        return serialization.load_der_public_key(key_bytes)
    raise InvalidInputError("Unknown key category.")

def encrypt_key_for_storage(key_id: str, raw_key: Any, category: str, password: str) -> str:
    """
    Encrypts a raw key into a secure JSON package using Argon2id and AES-256-GCM.
    """
    if not password:
        raise InvalidInputError("Password is required to encrypt key storage.")
        
    try:
        key_bytes = _serialize_for_storage(raw_key, category)
        salt = generate_kdf_salt()
        nonce = generate_random_bytes(KME_NONCE_SIZE)
        
        # Hardware-hard Argon2id derivation
        kek = derive_key(password, salt, "Argon2id", {"memory_cost": 65536, "time_cost": 3, "parallelism": 4})
        
        aad = text_to_bytes(f"KME-Storage|{key_id}|{category}")
        aesgcm = AESGCM(kek)
        ciphertext = aesgcm.encrypt(nonce, key_bytes, aad)
        
        package = {
            "format_version": "1.0",
            "key_id": key_id,
            "kdf": {
                "algorithm": "Argon2id",
                "salt": bytes_to_b64(salt)
            },
            "cipher": {
                "algorithm": "AES-256-GCM",
                "nonce": bytes_to_b64(nonce)
            },
            "encrypted_blob": bytes_to_b64(ciphertext)
        }
        return json.dumps(package)
    except Exception as e:
        raise CryptographicOperationError(f"Secure key wrapping failed: {str(e)}")

def decrypt_key_from_storage(payload_json: str, algorithm: str, category: str, password: str) -> Any:
    """
    Authenticates and decrypts a KME storage package back into a usable cryptographic key object.
    """
    try:
        payload = json.loads(payload_json)
        key_id = payload["key_id"]
        salt = b64_to_bytes(payload["kdf"]["salt"])
        nonce = b64_to_bytes(payload["cipher"]["nonce"])
        ciphertext = b64_to_bytes(payload["encrypted_blob"])
        
        kek = derive_key(password, salt, "Argon2id", {"memory_cost": 65536, "time_cost": 3, "parallelism": 4})
        aad = text_to_bytes(f"KME-Storage|{key_id}|{category}")
        
        aesgcm = AESGCM(kek)
        try:
            key_bytes = aesgcm.decrypt(nonce, ciphertext, aad)
        except InvalidTag:
            raise AuthenticationError("KME Decryption Failed: Invalid password or corrupted storage blob.")
            
        return _deserialize_from_storage(key_bytes, algorithm, category)
    except (AuthenticationError, CryptographicOperationError):
        raise
    except Exception as e:
        raise CryptographicOperationError(f"Secure key unwrapping failed: {str(e)}")

def create_backup_package(metadata_list: list, storage_list: list, backup_password: str) -> str:
    """Creates a unified, encrypted backup package containing multiple keys and their metadata."""
    backup_payload = json.dumps({"metadata": metadata_list, "storage": storage_list})
    
    salt = generate_kdf_salt()
    nonce = generate_random_bytes(KME_NONCE_SIZE)
    kek = derive_key(backup_password, salt, "Argon2id", {"memory_cost": 131072, "time_cost": 4, "parallelism": 4})
    
    aesgcm = AESGCM(kek)
    ciphertext = aesgcm.encrypt(nonce, text_to_bytes(backup_payload), text_to_bytes("KME-BACKUP-V1"))
    
    return json.dumps({
        "format": "KME-BACKUP-V1",
        "timestamp": time.time(),
        "salt": bytes_to_b64(salt),
        "nonce": bytes_to_b64(nonce),
        "data": bytes_to_b64(ciphertext)
    })

def restore_backup_package(backup_json: str, backup_password: str) -> Dict[str, Any]:
    """Authenticates and extracts a KME backup package."""
    try:
        pkg = json.loads(backup_json)
        if pkg.get("format") != "KME-BACKUP-V1":
            raise InvalidInputError("Unsupported backup format.")
            
        salt = b64_to_bytes(pkg["salt"])
        nonce = b64_to_bytes(pkg["nonce"])
        ciphertext = b64_to_bytes(pkg["data"])
        
        kek = derive_key(backup_password, salt, "Argon2id", {"memory_cost": 131072, "time_cost": 4, "parallelism": 4})
        aesgcm = AESGCM(kek)
        
        try:
            pt = aesgcm.decrypt(nonce, ciphertext, text_to_bytes("KME-BACKUP-V1"))
            return json.loads(bytes_to_text(pt))
        except InvalidTag:
            raise AuthenticationError("Backup Recovery Failed: Incorrect password or corrupted backup file.")
    except (AuthenticationError, CryptographicOperationError, InvalidInputError):
        raise
    except Exception as e:
        raise CryptographicOperationError(f"Backup restoration failed: {str(e)}")
