"""
Educational Session Key Management and Exchange Serialization Engine.
Manages X25519 public metadata and session lifecycles safely.
"""

import json
import uuid
import time
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from .exceptions import InvalidInputError, CryptographicOperationError
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes
from .public_key_manager import serialize_public_key, load_public_key

class SessionManager:
    """Manages ephemeral session metadata for educational demonstrations."""
    
    def __init__(self):
        self.sessions: Dict[str, Dict[str, Any]] = {}

    def create_session(self, context: str, salt: bytes) -> str:
        """Creates a new session and returns the session_id."""
        session_id = str(uuid.uuid4())
        self.sessions[session_id] = {
            "session_id": session_id,
            "context": context,
            "salt_b64": bytes_to_b64(salt),
            "created_at": time.time(),
            "status": "ACTIVE"
        }
        return session_id

    def terminate_session(self, session_id: str) -> None:
        """Terminates an active session."""
        if session_id not in self.sessions:
            raise InvalidInputError("Session ID not found.")
        self.sessions[session_id]["status"] = "TERMINATED"
        self.sessions[session_id]["terminated_at"] = time.time()

    def get_session(self, session_id: str) -> Dict[str, Any]:
        """Retrieves public session metadata."""
        if session_id not in self.sessions:
            raise InvalidInputError("Session ID not found.")
        return self.sessions[session_id]


def serialize_exchange_package(public_key: X25519PublicKey, salt: bytes, context: str, session_id: str) -> Dict[str, Any]:
    """
    Creates a versioned JSON exchange package containing strictly public metadata.
    NEVER includes private keys or raw shared secrets.
    """
    if not isinstance(public_key, X25519PublicKey):
        raise InvalidInputError("Provided key is not an X25519PublicKey.")
        
    try:
        pub_b64 = bytes_to_b64(serialize_public_key(public_key, fmt="DER"))
        salt_b64 = bytes_to_b64(salt)
        
        return {
            "format_version": "1.0",
            "algorithm": "X25519",
            "public_key": pub_b64,
            "kdf": "HKDF-SHA256",
            "kdf_salt": salt_b64,
            "context": context,
            "session_id": session_id
        }
    except Exception as e:
        raise CryptographicOperationError(f"Failed to serialize exchange package: {str(e)}")


def deserialize_exchange_package(payload_json: str) -> Dict[str, Any]:
    """
    Validates and deserializes an incoming exchange package.
    Extracts the peer's public key and KDF parameters safely.
    """
    try:
        payload = json.loads(payload_json)
        
        if payload.get("format_version") != "1.0":
            raise InvalidInputError("Unsupported format version. Expected '1.0'.")
            
        if payload.get("algorithm") != "X25519":
            raise InvalidInputError(f"Unsupported algorithm: {payload.get('algorithm')}")
            
        if payload.get("kdf") != "HKDF-SHA256":
            raise InvalidInputError(f"Unsupported KDF: {payload.get('kdf')}")
            
        pub_b64 = payload.get("public_key")
        salt_b64 = payload.get("kdf_salt")
        context = payload.get("context")
        session_id = payload.get("session_id")
        
        if not all([pub_b64, salt_b64, context, session_id]):
            raise InvalidInputError("Malformed exchange package. Missing required fields.")
            
        pub_bytes = b64_to_bytes(pub_b64)
        peer_public_key = load_public_key(pub_bytes)
        
        if not isinstance(peer_public_key, X25519PublicKey):
            raise InvalidInputError("Imported public key is not a valid X25519 key.")
            
        return {
            "peer_public_key": peer_public_key,
            "salt": b64_to_bytes(salt_b64),
            "context": context,
            "session_id": session_id
        }
        
    except json.JSONDecodeError:
        raise InvalidInputError("Payload is not valid JSON.")
    except InvalidInputError:
        raise
    except Exception as e:
        raise CryptographicOperationError(f"Failed to deserialize exchange package: {str(e)}")
