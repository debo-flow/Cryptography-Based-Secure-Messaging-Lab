"""
Advanced Message Authentication Engine (HMAC).
Implements HMAC-SHA256, HMAC-SHA384, and HMAC-SHA512.
Provides symmetric-key authenticated integrity for messages and large file streams.
"""

import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, IO
from cryptography.hazmat.primitives import hmac, hashes
from cryptography.exceptions import InvalidSignature

from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes
from .randomness import generate_random_bytes

HMAC_SUPPORTED_ALGOS = ["HMAC-SHA256", "HMAC-SHA384", "HMAC-SHA512"]

def _get_hash_instance(algorithm: str) -> hashes.HashAlgorithm:
    """Maps algorithm string to the appropriate cryptography hash primitive."""
    if algorithm == "HMAC-SHA256":
        return hashes.SHA256()
    elif algorithm == "HMAC-SHA384":
        return hashes.SHA384()
    elif algorithm == "HMAC-SHA512":
        return hashes.SHA512()
    else:
        raise InvalidInputError(f"Unsupported HMAC algorithm: {algorithm}")

def generate_hmac_key(length: int = 32) -> bytes:
    """Generates a cryptographically secure random key for HMAC."""
    if length < 16:
        raise InvalidInputError("HMAC key must be at least 16 bytes for adequate security.")
    return generate_random_bytes(length)

def get_key_identifier(key: bytes) -> str:
    """
    Calculates a non-secret key identifier (fingerprint) using SHA-256.
    Never exposes the raw key. Useful for tracking which key generated a tag.
    """
    digest = hashlib.sha256(key).hexdigest()
    return digest[:16].upper()  # 16 char hex identifier

def calculate_hmac(key: bytes, message: bytes, algorithm: str) -> bytes:
    """Calculates the raw HMAC tag for a given message."""
    try:
        hash_algo = _get_hash_instance(algorithm)
        h = hmac.HMAC(key, hash_algo)
        h.update(message)
        return h.finalize()
    except Exception as e:
        raise CryptographicOperationError(f"HMAC calculation failed: {str(e)}")

def verify_hmac(key: bytes, message: bytes, tag: bytes, algorithm: str) -> bool:
    """
    Verifies an HMAC tag using constant-time comparison natively provided by the library.
    Raises AuthenticationError on failure.
    """
    try:
        hash_algo = _get_hash_instance(algorithm)
        h = hmac.HMAC(key, hash_algo)
        h.update(message)
        h.verify(tag)
        return True
    except InvalidSignature:
        raise AuthenticationError("HMAC Verification Failed: The message was altered or the wrong key was used.")
    except Exception as e:
        raise CryptographicOperationError(f"HMAC verification process failed: {str(e)}")

def create_authentication_package(key: bytes, message: str, algorithm: str) -> Dict[str, Any]:
    """Generates a structured, versioned JSON package containing the message and HMAC tag."""
    if algorithm not in HMAC_SUPPORTED_ALGOS:
        raise InvalidInputError(f"Unsupported algorithm: {algorithm}")
    if not message:
        raise InvalidInputError("Message cannot be empty.")
        
    msg_bytes = text_to_bytes(message)
    tag = calculate_hmac(key, msg_bytes, algorithm)
    
    return {
        "format_version": "1.0",
        "authentication_type": "HMAC",
        "algorithm": algorithm,
        "message_encoding": "UTF-8",
        "message": bytes_to_b64(msg_bytes),
        "authentication_tag": bytes_to_b64(tag),
        "key_identifier": get_key_identifier(key),
        "created_at": datetime.now(timezone.utc).isoformat()
    }

def validate_authentication_package(key: bytes, payload_json: str) -> str:
    """Validates an HMAC JSON package and verifies authenticity. Returns plaintext message if valid."""
    try:
        payload = json.loads(payload_json)
        
        if payload.get("format_version") != "1.0":
            raise InvalidInputError("Unsupported format version.")
        if payload.get("authentication_type") != "HMAC":
            raise InvalidInputError("Payload is not an HMAC authentication package.")
            
        algo = payload.get("algorithm")
        msg_b64 = payload.get("message")
        tag_b64 = payload.get("authentication_tag")
        pkg_key_id = payload.get("key_identifier")
        
        if not all([algo, msg_b64, tag_b64, pkg_key_id]):
            raise InvalidInputError("Malformed HMAC package. Missing required fields.")
            
        actual_key_id = get_key_identifier(key)
        if actual_key_id != pkg_key_id:
            raise AuthenticationError(f"Key mismatch. Provided key ({actual_key_id}) != Package key ({pkg_key_id}).")
            
        msg_bytes = b64_to_bytes(msg_b64)
        tag_bytes = b64_to_bytes(tag_b64)
        
        verify_hmac(key, msg_bytes, tag_bytes, algo)
        return bytes_to_text(msg_bytes)
        
    except json.JSONDecodeError:
        raise InvalidInputError("Payload is not valid JSON.")
    except (InvalidInputError, AuthenticationError):
        raise
    except Exception as e:
        raise CryptographicOperationError(f"Package validation failed: {str(e)}")

def authenticate_file(key: bytes, file_stream: IO[bytes], algorithm: str) -> Dict[str, Any]:
    """Streams a file to calculate its HMAC without loading entirely into memory."""
    if algorithm not in HMAC_SUPPORTED_ALGOS:
        raise InvalidInputError(f"Unsupported algorithm: {algorithm}")
        
    try:
        hash_algo = _get_hash_instance(algorithm)
        h = hmac.HMAC(key, hash_algo)
        
        for chunk in iter(lambda: file_stream.read(4096), b""):
            h.update(chunk)
            
        tag = h.finalize()
        
        return {
            "format_version": "1.0",
            "authentication_type": "File-HMAC",
            "algorithm": algorithm,
            "message_encoding": "BINARY",
            "authentication_tag": bytes_to_b64(tag),
            "key_identifier": get_key_identifier(key),
            "created_at": datetime.now(timezone.utc).isoformat()
        }
    except Exception as e:
        raise CryptographicOperationError(f"File HMAC calculation failed: {str(e)}")

def verify_file_authentication(key: bytes, file_stream: IO[bytes], payload_json: str) -> str:
    """Streams a file and verifies its HMAC against the provided package metadata."""
    try:
        payload = json.loads(payload_json)
        
        if payload.get("format_version") != "1.0" or payload.get("authentication_type") != "File-HMAC":
            raise InvalidInputError("Invalid or unsupported File HMAC package.")
            
        algo = payload.get("algorithm")
        tag_b64 = payload.get("authentication_tag")
        pkg_key_id = payload.get("key_identifier")
        
        if not all([algo, tag_b64, pkg_key_id]):
            raise InvalidInputError("Malformed File HMAC package.")
            
        actual_key_id = get_key_identifier(key)
        if actual_key_id != pkg_key_id:
            raise AuthenticationError("Key mismatch.")
            
        tag_bytes = b64_to_bytes(tag_b64)
        hash_algo = _get_hash_instance(algo)
        h = hmac.HMAC(key, hash_algo)
        
        for chunk in iter(lambda: file_stream.read(4096), b""):
            h.update(chunk)
            
        try:
            h.verify(tag_bytes)
            return "FILE_AUTHENTICATED"
        except InvalidSignature:
            raise AuthenticationError("File HMAC Verification Failed: The file was altered or the wrong key was used.")
            
    except json.JSONDecodeError:
        raise InvalidInputError("Payload is not valid JSON.")
    except (InvalidInputError, AuthenticationError):
        raise
    except Exception as e:
        raise CryptographicOperationError(f"File verification failed: {str(e)}")
