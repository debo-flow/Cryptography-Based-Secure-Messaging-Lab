"""
Key, Nonce, and Salt Metadata Management.
"""
from dataclasses import dataclass
from enum import Enum
import time

class KeyStatus(Enum):
    ACTIVE = "Active"
    INACTIVE = "Inactive"
    EXPIRED = "Expired"
    REVOKED = "Revoked"

@dataclass
class KeyMetadata:
    key_id: str
    algorithm: str
    purpose: str
    status: KeyStatus
    version: int
    created_at: float = time.time()

@dataclass
class NonceMetadata:
    nonce_id: str
    algorithm: str
    associated_key_id: str
    created_at: float = time.time()
