"""
Advanced Secure Message Transmission Engine (M20).
Handles sequence counting, replay protection, and AEAD encapsulation for Duplex Messaging.
"""

import json
import uuid
import time
from datetime import datetime, timezone
from typing import Dict, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .randomness import generate_random_bytes
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes
from .e2ee import E2EESession, E2EE_SUPPORTED_CIPHERS, E2EE_NONCE_SIZE

def _build_transmission_aad(version: str, msg_id: str, session_id: str, sender_id: str, recipient_id: str, seq_num: int, algo: str, nonce_b64: str) -> bytes:
    """
    Constructs deterministic Additional Authenticated Data (AAD) mathematically binding 
    the plaintext to its exact routing parameters and sequence counter.
    """
    aad_str = f"{version}|{msg_id}|{session_id}|{sender_id}|{recipient_id}|{seq_num}|{algo}|{nonce_b64}"
    return text_to_bytes(aad_str)

def send_secure_message(session: E2EESession, plaintext: str, algorithm: str = "AES-256-GCM") -> Dict[str, Any]:
    """
    Encrypts a message using the sender's Tx key. Increments the Tx sequence counter to prevent replays.
    """
    if session.status != "ACTIVE":
        raise InvalidInputError("Cannot encrypt using a terminated or inactive session.")
    if algorithm not in E2EE_SUPPORTED_CIPHERS:
        raise InvalidInputError(f"Unsupported cipher: {algorithm}")
    if not plaintext:
        raise InvalidInputError("Cannot send an empty message.")
        
    try:
        msg_id = str(uuid.uuid4())
        nonce = generate_random_bytes(E2EE_NONCE_SIZE)
        nonce_b64 = bytes_to_b64(nonce)
        version = "2.0" # Upgraded to M20 specification
        
        # Increment local transmission sequence
        session.tx_sequence += 1
        seq_num = session.tx_sequence
        
        aad_bytes = _build_transmission_aad(version, msg_id, session.session_id, session.local_id, session.peer_id, seq_num, algorithm, nonce_b64)
        pt_bytes = text_to_bytes(plaintext)
        
        # Uses TX_KEY for encryption
        cipher = AESGCM(session.tx_key) if algorithm == "AES-256-GCM" else ChaCha20Poly1305(session.tx_key)
        ciphertext_with_tag = cipher.encrypt(nonce, pt_bytes, aad_bytes)
        
        return {
            "protocol_version": version,
            "message_id": msg_id,
            "session_id": session.session_id,
            "sender_id": session.local_id,
            "recipient_id": session.peer_id,
            "sequence_number": seq_num,
            "cipher": {
                "algorithm": algorithm,
                "nonce": nonce_b64
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ciphertext": bytes_to_b64(ciphertext_with_tag),
            "status": "QUEUED"
        }
    except Exception as e:
        raise CryptographicOperationError(f"E2EE Message Transmission failed: {str(e)}")

def receive_secure_message(session: E2EESession, payload_json: str) -> str:
    """
    Validates structure, strict routing/sequence metadata, and authenticates the ciphertext via AEAD.
    """
    if session.status != "ACTIVE":
        raise InvalidInputError("Cannot decrypt using a terminated session.")
        
    try:
        payload = json.loads(payload_json)
        
        version = payload.get("protocol_version")
        if version != "2.0": raise InvalidInputError(f"Unsupported protocol version: {version}")
            
        msg_id = payload.get("message_id")
        sess_id = payload.get("session_id")
        sender = payload.get("sender_id")
        recipient = payload.get("recipient_id")
        seq_num = payload.get("sequence_number")
        
        # 1. Routing Security Checks
        if sess_id != session.session_id: raise InvalidInputError("Message belongs to a different session.")
        if recipient != session.local_id: raise InvalidInputError("You are not the intended recipient of this message.")
        if sender != session.peer_id: raise InvalidInputError("Message sender does not match the active session peer.")
        
        # 2. Strict Replay & Ordering Protection
        if not isinstance(seq_num, int): raise InvalidInputError("Invalid sequence number format.")
        if seq_num <= session.rx_sequence:
            raise AuthenticationError(f"Replay Attack Detected: Sequence number {seq_num} has already been consumed or is out of order.")
            
        cipher_meta = payload.get("cipher", {})
        algo = cipher_meta.get("algorithm")
        nonce_b64 = cipher_meta.get("nonce")
        ct_b64 = payload.get("ciphertext")
        
        if not all([msg_id, algo, nonce_b64, ct_b64]): raise InvalidInputError("Malformed transmission package. Missing required fields.")
            
        nonce = b64_to_bytes(nonce_b64)
        if len(nonce) != E2EE_NONCE_SIZE: raise InvalidInputError("Invalid nonce length.")
        ciphertext_with_tag = b64_to_bytes(ct_b64)
        
        # 3. Reconstruct AAD for MAC verification
        aad_bytes = _build_transmission_aad(version, msg_id, sess_id, sender, recipient, seq_num, algo, nonce_b64)
        
        # Uses RX_KEY for decryption
        if algo == "AES-256-GCM": cipher = AESGCM(session.rx_key)
        elif algo == "ChaCha20-Poly1305": cipher = ChaCha20Poly1305(session.rx_key)
        else: raise InvalidInputError(f"Unsupported cipher: {algo}")
            
        try:
            # 4. Cryptographic Authentication & Decryption
            plaintext_bytes = cipher.decrypt(nonce, ciphertext_with_tag, aad_bytes)
            
            # 5. Commit sequence state ONLY after successful authentication
            session.rx_sequence = seq_num
            return bytes_to_text(plaintext_bytes)
            
        except InvalidTag:
            raise AuthenticationError("Authentication failed. Message tampered, or invalid session key.")
            
    except json.JSONDecodeError: raise InvalidInputError("Payload is not valid JSON.")
    except (AuthenticationError, InvalidInputError, CryptographicOperationError): raise
    except Exception as e: raise CryptographicOperationError(f"Message Reception failed: {str(e)}")
