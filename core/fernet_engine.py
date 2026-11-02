"""
Advanced Fernet Symmetric Encryption Engine.
Implements authenticated encryption using AES-128-CBC and HMAC-SHA256 natively via Fernet.
Supports JSON serialization, token expiration (TTL), and MultiFernet key rotation.
"""

import json
import time
import hashlib
import base64
from typing import Dict, Any, List, Optional
from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from datetime import datetime, timezone

from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .encoding import text_to_bytes, bytes_to_text

def generate_fernet_key() -> str:
    """Generates a secure URL-safe Base64-encoded 256-bit Fernet key."""
    return bytes_to_text(Fernet.generate_key())

def validate_fernet_key(key_b64: str) -> bytes:
    """Validates that a string is a valid Fernet key and returns its byte representation."""
    try:
        key_bytes = text_to_bytes(key_b64)
        Fernet(key_bytes) # Validates structure internally
        return key_bytes
    except (ValueError, TypeError, base64.binascii.Error):
        raise InvalidInputError("Invalid Fernet key format. Must be 32 URL-safe base64-encoded bytes.")
    except Exception as e:
        raise InvalidInputError(f"Fernet key validation failed: {str(e)}")

def fingerprint_fernet_key(key_b64: str) -> str:
    """Generates a SHA-256 fingerprint of the key for safe identification."""
    key_bytes = validate_fernet_key(key_b64)
    digest = hashlib.sha256(key_bytes).hexdigest()
    return ":".join(digest[i:i+2] for i in range(0, len(digest), 2)).upper()

def encrypt_fernet_text(key_b64: str, plaintext: str) -> Dict[str, Any]:
    """
    Encrypts UTF-8 plaintext using Fernet and serializes to a versioned JSON payload.
    """
    key_bytes = validate_fernet_key(key_b64)
    
    try:
        f = Fernet(key_bytes)
        pt_bytes = text_to_bytes(plaintext)
        token_bytes = f.encrypt(pt_bytes)
        
        created_at = Fernet.extract_timestamp(token_bytes)
        
        return {
            "format_version": "1.0",
            "algorithm": "Fernet",
            "key_id": fingerprint_fernet_key(key_b64),
            "token": bytes_to_text(token_bytes),
            "created_at": created_at,
            "encoding": "UTF-8"
        }
    except Exception as e:
        raise CryptographicOperationError(f"Fernet encryption failed: {str(e)}")

def decrypt_fernet_text(key_b64: str, payload_json: str, ttl: Optional[int] = None) -> str:
    """
    Decrypts a structured Fernet JSON payload. Validates TTL if provided.
    Returns plaintext strictly after authentication succeeds.
    """
    key_bytes = validate_fernet_key(key_b64)
    
    try:
        payload = json.loads(payload_json)
        
        if payload.get("format_version") != "1.0":
            raise InvalidInputError("Unsupported payload version. Expected '1.0'.")
            
        if payload.get("algorithm") != "Fernet":
            raise InvalidInputError(f"Unsupported algorithm: {payload.get('algorithm')}")
            
        token_str = payload.get("token")
        if not token_str:
            raise InvalidInputError("Malformed payload: Missing Fernet token.")
            
        token_bytes = text_to_bytes(token_str)
        f = Fernet(key_bytes)
        
        # Fernet natively handles MAC authentication and TTL expiration in decrypt()
        plaintext_bytes = f.decrypt(token_bytes, ttl=ttl)
        
        return bytes_to_text(plaintext_bytes)
        
    except InvalidToken:
        raise AuthenticationError("Authentication/Decryption failed. The token is invalid, tampered with, expired, or the wrong key was used.")
    except json.JSONDecodeError:
        raise InvalidInputError("Payload is not valid JSON.")
    except InvalidInputError:
        raise
    except Exception as e:
        raise CryptographicOperationError(f"Fernet decryption engine failure: {str(e)}")

def rotate_fernet_token(primary_key_b64: str, old_keys_b64: List[str], payload_json: str) -> Dict[str, Any]:
    """
    Uses MultiFernet to rotate an old token to the new primary key while preserving the timestamp.
    """
    try:
        primary_key_bytes = validate_fernet_key(primary_key_b64)
        fernet_list = [Fernet(primary_key_bytes)]
        
        for k in old_keys_b64:
            fernet_list.append(Fernet(validate_fernet_key(k)))
            
        mf = MultiFernet(fernet_list)
        
        payload = json.loads(payload_json)
        old_token_bytes = text_to_bytes(payload["token"])
        
        # MultiFernet decrypts using whichever key works, then encrypts using the primary key
        new_token_bytes = mf.rotate(old_token_bytes)
        
        return {
            "format_version": "1.0",
            "algorithm": "Fernet",
            "key_id": fingerprint_fernet_key(primary_key_b64),
            "token": bytes_to_text(new_token_bytes),
            "created_at": Fernet.extract_timestamp(new_token_bytes),
            "encoding": "UTF-8"
        }
    except InvalidToken:
        raise AuthenticationError("Rotation failed. None of the provided keys could authenticate the token.")
    except Exception as e:
        raise CryptographicOperationError(f"Key rotation failed: {str(e)}")

def inspect_fernet_token(token_str: str) -> Dict[str, Any]:
    """Extracts unencrypted metadata (like timestamp) directly from the token."""
    try:
        token_bytes = text_to_bytes(token_str)
        ts = Fernet.extract_timestamp(token_bytes)
        age_seconds = int(time.time()) - ts
        
        dt_utc = datetime.fromtimestamp(ts, tz=timezone.utc)
        
        return {
            "token_length": len(token_bytes),
            "timestamp": ts,
            "created_at_utc": dt_utc.strftime('%Y-%m-%d %H:%M:%S UTC'),
            "age_seconds": age_seconds
        }
    except Exception as e:
        raise InvalidInputError(f"Could not parse Fernet token metadata: {str(e)}")
