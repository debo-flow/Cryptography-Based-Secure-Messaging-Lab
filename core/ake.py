"""
Authenticated Key Exchange (AKE) Engine.
Implements a cryptographically sound, Ed25519-signed X25519 Key Exchange.
Provides Transcript Hashing, Directional Session Keys, Mutual Confirmation, and Replay Protection.
"""

import time
import hashlib
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .encoding import text_to_bytes, bytes_to_b64, b64_to_bytes
from .randomness import generate_random_bytes
from .x25519 import derive_x25519_shared_secret, serialize_x25519_public_key, derive_hkdf_key
from .ed25519 import sign_message, verify_signature
from .hmac_engine import calculate_hmac, verify_hmac

AKE_NONCE_SIZE = 32
AKE_EXPIRATION_WINDOW = 300 # 5 minutes for replay protection

# Replay Cache (In-memory simulation for educational purposes)
_REPLAY_CACHE: Dict[str, float] = {}

def generate_ake_nonce() -> bytes:
    """Generates a fresh 32-byte cryptographic nonce for handshakes."""
    return generate_random_bytes(AKE_NONCE_SIZE)

def build_canonical_transcript(
    version: str, session_id: str,
    init_id: str, resp_id: str,
    init_id_fp: str, resp_id_fp: str,
    init_eph_pub_b64: str, resp_eph_pub_b64: str,
    init_nonce_b64: str, resp_nonce_b64: str,
    algorithm_suite: str, timestamp: float
) -> bytes:
    """
    Constructs a deterministic, strict byte-string binding all handshake parameters.
    Prevents downgrade attacks, identity misbinding, and MITM tampering.
    """
    transcript_str = (
        f"{version}|{session_id}|"
        f"{init_id}|{resp_id}|"
        f"{init_id_fp}|{resp_id_fp}|"
        f"{init_eph_pub_b64}|{resp_eph_pub_b64}|"
        f"{init_nonce_b64}|{resp_nonce_b64}|"
        f"{algorithm_suite}|{timestamp}"
    )
    return text_to_bytes(transcript_str)

def hash_transcript(transcript: bytes) -> bytes:
    """Hashes the canonical transcript using SHA-256 for signing and key derivation."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(transcript)
    return digest.finalize()

def verify_replay_protection(session_id: str, timestamp: float) -> None:
    """Simulates Replay Protection by checking expiration windows and duplicate IDs."""
    now = time.time()
    if now - timestamp > AKE_EXPIRATION_WINDOW or timestamp > now + 5:
        raise AuthenticationError("Handshake rejected: Timestamp expired or invalid (Replay Protection).")
    
    if session_id in _REPLAY_CACHE:
        raise AuthenticationError("Handshake rejected: Session ID already consumed (Replay Protection).")
        
    _REPLAY_CACHE[session_id] = now
    
    # Cleanup old entries (Educational garbage collection)
    expired = [sid for sid, ts in _REPLAY_CACHE.items() if now - ts > AKE_EXPIRATION_WINDOW]
    for sid in expired:
        del _REPLAY_CACHE[sid]

def derive_directional_keys(shared_secret: bytes, transcript_hash: bytes) -> Tuple[bytes, bytes, bytes]:
    """
    Derives independent keys for Initiator Tx, Responder Tx, and Mutual Confirmation.
    Uses the Transcript Hash as the HKDF salt, mathematically binding the keys to the un-tampered handshake.
    """
    init_tx_key = derive_hkdf_key(shared_secret, transcript_hash, "Initiator-Tx-Key", 32)
    resp_tx_key = derive_hkdf_key(shared_secret, transcript_hash, "Responder-Tx-Key", 32)
    confirmation_key = derive_hkdf_key(shared_secret, transcript_hash, "Mutual-Confirmation-Key", 32)
    return init_tx_key, resp_tx_key, confirmation_key

def generate_session_confirmation(confirmation_key: bytes, transcript_hash: bytes, role: str) -> str:
    """Generates an HMAC confirming successful key derivation based on the assigned role."""
    if role not in ["INITIATOR", "RESPONDER"]:
        raise InvalidInputError("Invalid role for confirmation.")
    payload = transcript_hash + text_to_bytes(role)
    mac = calculate_hmac(confirmation_key, payload, "HMAC-SHA256")
    return bytes_to_b64(mac)

def verify_session_confirmation(confirmation_key: bytes, transcript_hash: bytes, role: str, provided_mac_b64: str) -> None:
    """Verifies the peer's session confirmation HMAC."""
    if role not in ["INITIATOR", "RESPONDER"]:
        raise InvalidInputError("Invalid role for confirmation.")
    payload = transcript_hash + text_to_bytes(role)
    try:
        verify_hmac(confirmation_key, payload, b64_to_bytes(provided_mac_b64), "HMAC-SHA256")
    except AuthenticationError:
        raise AuthenticationError(f"Mutual Confirmation Failed for {role}. Handshake aborted.")
