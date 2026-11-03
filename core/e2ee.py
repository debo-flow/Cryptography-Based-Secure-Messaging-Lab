"""
End-to-End Encrypted (E2EE) Messaging Foundation.
Provides Identity Management, X25519 Session Establishment, and AEAD Messaging.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .randomness import generate_random_bytes
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes
from .x25519 import generate_x25519_key_pair, derive_shared_secret, derive_encryption_key, generate_hkdf_salt
from .ed25519 import generate_ed25519_key_pair
from .public_key_manager import get_public_key_fingerprint

E2EE_SUPPORTED_CIPHERS = ["AES-256-GCM", "ChaCha20-Poly1305"]
E2EE_NONCE_SIZE = 12 # 96 bits for both GCM and Poly1305

class UserIdentity:
    """Represents a simulated user identity in the E2EE system."""
    def __init__(self, user_id: str):
        self.user_id = user_id
        # X25519 used for Key Exchange
        self.x25519_priv, self.x25519_pub = generate_x25519_key_pair()
        # Ed25519 provisioned for Future Milestone (Identity Authentication)
        self.ed25519_priv, self.ed25519_pub = generate_ed25519_key_pair()
        
    def get_public_metadata(self) -> Dict[str, str]:
        """Returns non-secret identity metadata."""
        return {
            "user_id": self.user_id,
            "x25519_fingerprint": get_public_key_fingerprint(self.x25519_pub),
            "ed25519_fingerprint": get_public_key_fingerprint(self.ed25519_pub)
        }

class E2EESession:
    """Represents a localized active messaging session for a user."""
    def __init__(self, session_id: str, derived_key: bytes, local_id: str, peer_id: str):
        self.session_id = session_id
        self.derived_key = derived_key
        self.local_id = local_id
        self.peer_id = peer_id
        self.status = "ACTIVE"
        self.created_at = datetime.now(timezone.utc).isoformat()
        
    def terminate(self):
        self.status = "TERMINATED"
        self.derived_key = b"" # Explicitly wipe the key in memory

def simulate_session_establishment(alice: UserIdentity, bob: UserIdentity) -> Tuple[E2EESession, E2EESession]:
    """
    Simulates a secure X25519 Key Exchange between two parties, deriving independent session objects.
    WARNING: In a real protocol, salt is exchanged over the wire. Here it is simulated as agreed metadata.
    """
    session_id = str(uuid.uuid4())
    salt = generate_hkdf_salt()
    context = f"E2EE-Session-{session_id}"
    
    # Alice derives secret using her private + Bob's public
    a_secret = derive_shared_secret(alice.x25519_priv, bob.x25519_pub)
    a_key = derive_encryption_key(a_secret, salt, context)
    session_alice = E2EESession(session_id, a_key, alice.user_id, bob.user_id)
    
    # Bob derives secret using his private + Alice's public
    b_secret = derive_shared_secret(bob.x25519_priv, alice.x25519_pub)
    b_key = derive_encryption_key(b_secret, salt, context)
    session_bob = E2EESession(session_id, b_key, bob.user_id, alice.user_id)
    
    return session_alice, session_bob

def _build_e2ee_aad(version: str, msg_id: str, session_id: str, sender_id: str, recipient_id: str, algo: str, nonce_b64: str, user_aad: str) -> bytes:
    """Deterministically binds all routing and cryptographic metadata to the AEAD MAC tag."""
    aad_str = f"{version}|{msg_id}|{session_id}|{sender_id}|{recipient_id}|{algo}|{nonce_b64}|{user_aad}"
    return text_to_bytes(aad_str)

def encrypt_e2ee_message(session: E2EESession, plaintext: str, algorithm: str = "AES-256-GCM", user_aad: str = "") -> Dict[str, Any]:
    """
    Encrypts a message for the E2EE session. Generates a fresh nonce and binds metadata.
    """
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
        
        if algorithm == "AES-256-GCM":
            cipher = AESGCM(session.derived_key)
        else:
            cipher = ChaCha20Poly1305(session.derived_key)
            
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
    """
    Validates structure, routing metadata, and strictly authenticates the ciphertext via AEAD.
    """
    if session.status != "ACTIVE":
        raise InvalidInputError("Cannot decrypt using a terminated session.")
        
    try:
        payload = json.loads(payload_json)
        
        version = payload.get("protocol_version")
        if version != "1.0":
            raise InvalidInputError("Unsupported protocol version.")
            
        msg_id = payload.get("message_id")
        sess_id = payload.get("session_id")
        sender = payload.get("sender_id")
        recipient = payload.get("recipient_id")
        
        # Routing Security Checks
        if sess_id != session.session_id:
            raise InvalidInputError("Message belongs to a different session.")
        if recipient != session.local_id:
            raise InvalidInputError("You are not the intended recipient of this message.")
        if sender != session.peer_id:
            raise InvalidInputError("Message sender does not match the active session peer.")
            
        cipher_meta = payload.get("cipher", {})
        algo = cipher_meta.get("algorithm")
        nonce_b64 = cipher_meta.get("nonce")
        user_aad_b64 = payload.get("aad", "")
        ct_b64 = payload.get("ciphertext")
        
        if not all([msg_id, algo, nonce_b64, ct_b64]):
            raise InvalidInputError("Malformed E2EE package. Missing required fields.")
            
        nonce = b64_to_bytes(nonce_b64)
        if len(nonce) != E2EE_NONCE_SIZE:
            raise InvalidInputError("Invalid nonce length.")
            
        ciphertext_with_tag = b64_to_bytes(ct_b64)
        user_aad = bytes_to_text(b64_to_bytes(user_aad_b64)) if user_aad_b64 else ""
        
        aad_bytes = _build_e2ee_aad(version, msg_id, sess_id, sender, recipient, algo, nonce_b64, user_aad)
        
        if algo == "AES-256-GCM":
            cipher = AESGCM(session.derived_key)
        elif algo == "ChaCha20-Poly1305":
            cipher = ChaCha20Poly1305(session.derived_key)
        else:
            raise InvalidInputError(f"Unsupported cipher: {algo}")
            
        try:
            plaintext_bytes = cipher.decrypt(nonce, ciphertext_with_tag, aad_bytes)
            return bytes_to_text(plaintext_bytes)
        except InvalidTag:
            raise AuthenticationError("Authentication failed. Message tampered, or invalid session key.")
            
    except json.JSONDecodeError:
        raise InvalidInputError("Payload is not valid JSON.")
    except (AuthenticationError, InvalidInputError, CryptographicOperationError):
        raise
    except Exception as e:
        raise CryptographicOperationError(f"E2EE Decryption failed: {str(e)}")
