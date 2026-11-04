"""
Educational Cryptographic Ratchet & Forward Secrecy Engine (M32).
Demonstrates Key Evolution, Forward Secrecy, and Post-Compromise Security (PCS).
Strictly avoids storing chain keys or message keys on disk.
"""

import time
import uuid
import json
from enum import Enum
from typing import Dict, Any, Tuple, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from .exceptions import CryptographicOperationError, AuthenticationError, InvalidInputError
from .randomness import generate_random_bytes
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes
from .x25519 import generate_x25519_key_pair, derive_x25519_shared_secret, serialize_x25519_public_key, derive_hkdf_key

class RatchetStatus(Enum):
    ACTIVE = "ACTIVE"
    COMPROMISED = "COMPROMISED"
    RECOVERED = "RECOVERED"
    TERMINATED = "TERMINATED"
    EXPIRED = "EXPIRED"

class ChainKeyManager:
    """Manages the evolution of a single directional cryptographic chain."""
    def __init__(self, initial_chain_key: bytes):
        self.current_chain_key = initial_chain_key
        self.sequence = 0
        self.skipped_message_keys: Dict[int, bytes] = {}
        self.MAX_SKIP = 50 # Bounded out-of-order handling

    def next_message_key(self) -> Tuple[bytes, int]:
        """Advances the ratchet. Generates a Message Key and a NEW Chain Key."""
        # Use HKDF to evolve the chain key and extract a message key simultaneously.
        # This mathematically ensures Forward Secrecy: Knowing MK_n does not reveal CK_n or MK_n-1.
        mk = derive_hkdf_key(self.current_chain_key, b"MessageKey", "RATCHET_MK", 32)
        next_ck = derive_hkdf_key(self.current_chain_key, b"ChainKey", "RATCHET_CK", 32)
        
        self.current_chain_key = next_ck
        self.sequence += 1
        return mk, self.sequence

class RatchetSession:
    """Maintains the full state for an E2E Ratchet Session between two parties."""
    def __init__(self, session_id: str, local_id: str, peer_id: str, initial_root_key: bytes, is_initiator: bool):
        self.session_id = session_id
        self.local_id = local_id
        self.peer_id = peer_id
        
        self.generation = 1
        self.status = RatchetStatus.ACTIVE
        self.expires_at = time.time() + 86400
        
        # Derive initial sending and receiving chain keys from the root key
        tx_seed = derive_hkdf_key(initial_root_key, b"Init", "TX_CHAIN_SEED" if is_initiator else "RX_CHAIN_SEED", 32)
        rx_seed = derive_hkdf_key(initial_root_key, b"Init", "RX_CHAIN_SEED" if is_initiator else "TX_CHAIN_SEED", 32)
        
        self.tx_chain = ChainKeyManager(tx_seed)
        self.rx_chain = ChainKeyManager(rx_seed)
        self.root_key = initial_root_key
        self.cipher_suite = "AES-256-GCM"

    def validate_state(self):
        if self.status in [RatchetStatus.TERMINATED, RatchetStatus.EXPIRED]:
            raise CryptographicOperationError(f"Cannot operate on session with status: {self.status.value}")
        if time.time() > self.expires_at:
            self.status = RatchetStatus.EXPIRED
            raise CryptographicOperationError("Ratchet session has expired.")

    def simulate_compromise(self):
        """Simulates an attacker extracting the current root and chain keys from RAM."""
        self.status = RatchetStatus.COMPROMISED

    def perform_post_compromise_recovery(self, peer_ephemeral_pub: Any) -> Any:
        """
        Executes an Ephemeral Key Exchange to generate a fresh root key.
        This provides Post-Compromise Security (PCS). Future messages are secure again.
        Returns the new local ephemeral public key to send to the peer.
        """
        self.validate_state()
        new_priv, new_pub = generate_x25519_key_pair()
        dh_out = derive_x25519_shared_secret(new_priv, peer_ephemeral_pub)
        
        # Mix the new DH output with the old root key to advance the root chain
        self.root_key = derive_hkdf_key(self.root_key, dh_out, "PCS_ROOT_RATCHET", 32)
        
        # Reset the chains based on the new uncompromised root key
        new_tx = derive_hkdf_key(self.root_key, b"PCS", "TX_CHAIN_SEED", 32)
        new_rx = derive_hkdf_key(self.root_key, b"PCS", "RX_CHAIN_SEED", 32)
        
        self.tx_chain = ChainKeyManager(new_tx)
        self.rx_chain = ChainKeyManager(new_rx)
        self.generation += 1
        
        self.status = RatchetStatus.RECOVERED
        return new_pub

class RatchetManager:
    """Handles encryption and decryption tying into the Ratchet chains and AES/ChaCha20."""
    
    @staticmethod
    def _build_aad(s_id: str, sender: str, seq: int, gen: int, nonce_b64: str) -> bytes:
        return text_to_bytes(f"RATCHET_V1|{s_id}|{sender}|{seq}|{gen}|{nonce_b64}")

    @staticmethod
    def encrypt_message(session: RatchetSession, plaintext: str) -> Dict[str, Any]:
        session.validate_state()
        
        # Evolve the chain and extract a single-use message key
        mk, seq = session.tx_chain.next_message_key()
        nonce = generate_random_bytes(12)
        nonce_b64 = bytes_to_b64(nonce)
        
        aad = RatchetManager._build_aad(session.session_id, session.local_id, seq, session.generation, nonce_b64)
        
        cipher = AESGCM(mk) if session.cipher_suite == "AES-256-GCM" else ChaCha20Poly1305(mk)
        ct_tag = cipher.encrypt(nonce, text_to_bytes(plaintext), aad)
        
        # Memory cleanup hint (Python garbage collection handles actual wipe)
        del mk 
        
        return {
            "session_id": session.session_id,
            "sender_id": session.local_id,
            "ratchet_generation": session.generation,
            "sequence_number": seq,
            "nonce": nonce_b64,
            "ciphertext": bytes_to_b64(ct_tag)
        }

    @staticmethod
    def decrypt_message(session: RatchetSession, payload_json: str) -> str:
        session.validate_state()
        
        try:
            payload = json.loads(payload_json)
            if payload["session_id"] != session.session_id:
                raise InvalidInputError("Session ID Mismatch.")
                
            seq = payload["sequence_number"]
            gen = payload["ratchet_generation"]
            
            # Sequence Validation & Bounded Out-Of-Order Handling
            if gen != session.generation:
                raise AuthenticationError(f"Generation mismatch. Expected {session.generation}, got {gen}. A PCS recovery may have occurred.")
                
            if seq <= session.rx_chain.sequence:
                # Check if it's a skipped message
                if seq in session.rx_chain.skipped_message_keys:
                    mk = session.rx_chain.skipped_message_keys.pop(seq)
                else:
                    raise AuthenticationError(f"Replay Attack or Duplicate ID! Sequence {seq} has already been processed.")
            else:
                # Fast-forward ratchet if messages were skipped
                skip_count = seq - session.rx_chain.sequence - 1
                if skip_count > session.rx_chain.MAX_SKIP:
                    raise AuthenticationError(f"Too many skipped messages ({skip_count}). Maximum allowed is {session.rx_chain.MAX_SKIP}.")
                
                # Store skipped keys
                while session.rx_chain.sequence < seq - 1:
                    skipped_mk, skipped_seq = session.rx_chain.next_message_key()
                    session.rx_chain.skipped_message_keys[skipped_seq] = skipped_mk
                
                # Evolve to the actual message key
                mk, _ = session.rx_chain.next_message_key()

            # Authenticated Decryption
            nonce_b64 = payload["nonce"]
            nonce = b64_to_bytes(nonce_b64)
            ct = b64_to_bytes(payload["ciphertext"])
            
            aad = RatchetManager._build_aad(session.session_id, payload["sender_id"], seq, gen, nonce_b64)
            
            cipher = AESGCM(mk) if session.cipher_suite == "AES-256-GCM" else ChaCha20Poly1305(mk)
            try:
                plaintext = cipher.decrypt(nonce, ct, aad)
                del mk
                return bytes_to_text(plaintext)
            except InvalidTag:
                raise AuthenticationError("AEAD Verification Failed! Ciphertext or metadata was modified.")
                
        except (AuthenticationError, InvalidInputError): raise
        except Exception as e: raise CryptographicOperationError(f"Ratchet Decryption Error: {str(e)}")

class RatchetSecurityAnalyzer:
    """Evaluates Ratchet state to detect security anomalies."""
    @staticmethod
    def analyze_session(session: RatchetSession) -> List[Dict[str, str]]:
        findings = []
        if session.status == RatchetStatus.COMPROMISED:
            findings.append({
                "severity": "Critical",
                "description": "Session keys extracted from memory.",
                "evidence": f"Status: {session.status.value}",
                "impact": "Current and future messages are compromised until a PCS recovery is executed.",
                "remediation": "Execute Post-Compromise Security (PCS) recovery via Ephemeral DH agreement."
            })
        
        if len(session.rx_chain.skipped_message_keys) > 10:
            findings.append({
                "severity": "Medium",
                "description": "High number of skipped message keys retained in memory.",
                "evidence": f"Skipped keys count: {len(session.rx_chain.skipped_message_keys)}",
                "impact": "Increases exposure if device is compromised.",
                "remediation": "Implement strict time-based eviction for skipped message keys."
            })
            
        return findings
