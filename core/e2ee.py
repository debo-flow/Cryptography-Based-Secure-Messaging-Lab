"""
End-to-End Encrypted (E2EE) Messaging Foundation.
Upgraded in M19/M20 to support Authenticated Key Exchange (AKE) and Sequence Monotonicity.
"""

import json
import uuid
from datetime import datetime, timezone
from typing import Dict, Any, Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .randomness import generate_random_bytes
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes
from .ed25519 import generate_ed25519_key_pair
from .public_key_manager import get_public_key_fingerprint

E2EE_SUPPORTED_CIPHERS = ["AES-256-GCM", "ChaCha20-Poly1305"]
E2EE_NONCE_SIZE = 12 

class UserIdentity:
    def __init__(self, user_id: str):
        self.user_id = user_id
        self.identity_priv, self.identity_pub = generate_ed25519_key_pair()
        
    def get_public_metadata(self) -> Dict[str, str]:
        return {
            "user_id": self.user_id,
            "identity_fingerprint": get_public_key_fingerprint(self.identity_pub)
        }

class E2EESession:
    """Represents a localized active messaging session using Directional Keys and Sequence Counters (M20)."""
    def __init__(self, session_id: str, tx_key: bytes, rx_key: bytes, local_id: str, peer_id: str):
        self.session_id = session_id
        self.tx_key = tx_key
        self.rx_key = rx_key
        self.local_id = local_id
        self.peer_id = peer_id
        self.tx_sequence = 0
        self.rx_sequence = 0
        self.status = "ACTIVE"
        self.created_at = datetime.now(timezone.utc).isoformat()
        
    def terminate(self):
        self.status = "TERMINATED"
        self.tx_key = b"" 
        self.rx_key = b""
