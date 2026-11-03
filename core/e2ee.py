"""
End-to-End Encrypted (E2EE) Messaging Foundation.
Upgraded in M19 to support Authenticated Key Exchange (AKE) and Directional Session Keys.
"""

import json
import uuid
import time
from datetime import datetime, timezone
from typing import Dict, Any, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidTag

from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .randomness import generate_random_bytes
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes
from .x25519 import generate_x25519_key_pair, derive_x25519_shared_secret, serialize_x25519_public_key
from .ed25519 import generate_ed25519_key_pair, sign_message, verify_signature
from .public_key_manager import get_public_key_fingerprint

from .ake import (
    generate_ake_nonce, build_canonical_transcript, hash_transcript, 
    verify_replay_protection, derive_directional_keys, 
    generate_session_confirmation, verify_session_confirmation
)

E2EE_SUPPORTED_CIPHERS = ["AES-256-GCM", "ChaCha20-Poly1305"]
E2EE_NONCE_SIZE = 12 

class UserIdentity:
    def __init__(self, user_id: str):
        self.user_id = user_id
        # Ed25519 Identity Key (Long Term)
        self.identity_priv, self.identity_pub = generate_ed25519_key_pair()
        
    def get_public_metadata(self) -> Dict[str, str]:
        return {
            "user_id": self.user_id,
            "identity_fingerprint": get_public_key_fingerprint(self.identity_pub)
        }

class E2EESession:
    """Represents a localized active messaging session using Directional Keys (M19)."""
    def __init__(self, session_id: str, tx_key: bytes, rx_key: bytes, local_id: str, peer_id: str):
        self.session_id = session_id
        self.tx_key = tx_key
        self.rx_key = rx_key
        self.local_id = local_id
        self.peer_id = peer_id
        self.status = "ACTIVE"
        self.created_at = datetime.now(timezone.utc).isoformat()
        
    def terminate(self):
        self.status = "TERMINATED"
        self.tx_key = b"" 
        self.rx_key = b""

def perform_authenticated_key_exchange(alice: UserIdentity, bob: UserIdentity, suite: str = "X25519-Ed25519-AES256GCM") -> Tuple[E2EESession, E2EESession]:
    """
    Executes the full Authenticated Key Exchange (AKE) protocol.
    Provides Identity verification, Downgrade protection, Replay protection, and Mutual Confirmation.
    """
    session_id = str(uuid.uuid4())
    ts = time.time()
    
    # 1. Ephemeral Key Generation
    a_eph_priv, a_eph_pub = generate_x25519_key_pair()
    b_eph_priv, b_eph_pub = generate_x25519_key_pair()
    
    # 2. Nonce Generation
    a_nonce = bytes_to_b64(generate_ake_nonce())
    b_nonce = bytes_to_b64(generate_ake_nonce())
    
    # 3. Canonical Transcript Construction
    transcript = build_canonical_transcript(
        "1.0", session_id, alice.user_id, bob.user_id,
        get_public_key_fingerprint(alice.identity_pub), get_public_key_fingerprint(bob.identity_pub),
        serialize_x25519_public_key(a_eph_pub), serialize_x25519_public_key(b_eph_pub),
        a_nonce, b_nonce, suite, ts
    )
    t_hash = hash_transcript(transcript)
    
    # 4. Identity Authentication (Signatures over Transcript)
    a_sig = sign_message(alice.identity_priv, transcript)
    b_sig = sign_message(bob.identity_priv, transcript)
    
    # 5. Verification & Replay Protection (Bob verifies Alice, Alice verifies Bob)
    verify_replay_protection(session_id, ts)
    verify_signature(alice.identity_pub, a_sig, transcript)
    verify_signature(bob.identity_pub, b_sig, transcript)
    
    # 6. Shared Secret Derivation
    a_secret = derive_x25519_shared_secret(a_eph_priv, b_eph_pub)
    b_secret = derive_x25519_shared_secret(b_eph_priv, a_eph_pub)
    
    # 7. Directional Session Key Derivation (using Transcript Hash as Salt)
    a_tx, a_rx, a_conf = derive_directional_keys(a_secret, t_hash)
    b_tx, b_rx, b_conf = derive_directional_keys(b_secret, t_hash)
    
    # 8. Mutual Session Confirmation
    a_proof = generate_session_confirmation(a_conf, t_hash, "INITIATOR")
    b_proof = generate_session_confirmation(b_conf, t_hash, "RESPONDER")
    verify_session_confirmation(b_conf, t_hash, "INITIATOR", a_proof)
    verify_session_confirmation(a_conf, t_hash, "RESPONDER", b_proof)
    
    # 9. Session Established
    session_alice = E2EESession(session_id, a_tx, a_rx, alice.user_id, bob.user_id)
    session_bob = E2EESession(session_id, b_tx, b_rx, bob.user_id, alice.user_id)
    
    return session_alice, session_bob

def _build_e2ee_aad(version: str, msg_id: str, session_id: str, sender_id: str, recipient_id: str, algo: str, nonce_b64: str, user_aad: str) -> bytes:
    aad_str = f"{version}|{msg_id}|{session_id}|{sender_id}|{recipient_id}|{algo}|{nonce_b64}|{user_aad}"
    return text_to_bytes(aad_str)

def encrypt_e2ee_message(session: E2EESession, plaintext: str, algorithm: str = "AES-256-GCM", user_aad: str = "") -> Dict[str, Any]:
    if session.status != "ACTIVE":
        raise InvalidInputError("Cannot encrypt using a terminated session.")
    if algorithm not in E2EE_SUPPORTED_CIPHERS:
        raise InvalidInputError(f"Unsupported cipher: {algorithm}")
        
    try:
        msg_id = str(uuid.uuid4())
        nonce = generate_random_bytes(E2EE_NONCE_SIZE)
        nonce_b64 = bytes_to_b64(nonce)
        version = "1.0"
        
        aad_bytes = _build_e2ee_aad(version, msg_id, session.session_id, session.local_id, session.peer_id, algorithm, nonce_b64, user_aad)
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
            "cipher": {
                "algorithm": algorithm,
                "nonce": nonce_b64
            },
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "aad": bytes_to_b64(text_to_bytes(user_aad)) if user_aad else "",
            "ciphertext": bytes_to_b64(ciphertext_with_tag)
        }
    except Exception as e:
        raise CryptographicOperationError(f"E2EE Encryption failed: {str(e)}")

def decrypt_e2ee_message(session: E2EESession, payload_json: str) -> str:
    if session.status != "ACTIVE":
        raise InvalidInputError("Cannot decrypt using a terminated session.")
        
    try:
        payload = json.loads(payload_json)
        
        version = payload.get("protocol_version")
        if version != "1.0": raise InvalidInputError("Unsupported protocol version.")
            
        msg_id = payload.get("message_id")
        sess_id = payload.get("session_id")
        sender = payload.get("sender_id")
        recipient = payload.get("recipient_id")
        
        if sess_id != session.session_id: raise InvalidInputError("Message belongs to a different session.")
        if recipient != session.local_id: raise InvalidInputError("You are not the intended recipient.")
        if sender != session.peer_id: raise InvalidInputError("Message sender does not match the active session peer.")
            
        cipher_meta = payload.get("cipher", {})
        algo = cipher_meta.get("algorithm")
        nonce_b64 = cipher_meta.get("nonce")
        user_aad_b64 = payload.get("aad", "")
        ct_b64 = payload.get("ciphertext")
        
        if not all([msg_id, algo, nonce_b64, ct_b64]): raise InvalidInputError("Malformed E2EE package.")
            
        nonce = b64_to_bytes(nonce_b64)
        ciphertext_with_tag = b64_to_bytes(ct_b64)
        user_aad = bytes_to_text(b64_to_bytes(user_aad_b64)) if user_aad_b64 else ""
        
        aad_bytes = _build_e2ee_aad(version, msg_id, sess_id, sender, recipient, algo, nonce_b64, user_aad)
        
        # Uses RX_KEY for decryption
        if algo == "AES-256-GCM": cipher = AESGCM(session.rx_key)
        elif algo == "ChaCha20-Poly1305": cipher = ChaCha20Poly1305(session.rx_key)
        else: raise InvalidInputError(f"Unsupported cipher: {algo}")
            
        try:
            plaintext_bytes = cipher.decrypt(nonce, ciphertext_with_tag, aad_bytes)
            return bytes_to_text(plaintext_bytes)
        except InvalidTag:
            raise AuthenticationError("Authentication failed. Message tampered, or invalid session key.")
            
    except json.JSONDecodeError: raise InvalidInputError("Payload is not valid JSON.")
    except (AuthenticationError, InvalidInputError, CryptographicOperationError): raise
    except Exception as e: raise CryptographicOperationError(f"E2EE Decryption failed: {str(e)}")
