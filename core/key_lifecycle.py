"""
Advanced Cryptographic Key Rotation & Lifecycle Management System (M33).
Manages Key Evolution, Rotation, Revocation, Dependency Graphing, and Secure Backups.
Integrates tightly with the existing M22 KMS engine.
"""

import time
import uuid
import json
from enum import Enum
from typing import Dict, Any, List, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from .exceptions import CryptographicOperationError, AuthenticationError, InvalidInputError
from .randomness import generate_random_bytes
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes
from .pbe import encrypt_with_password, decrypt_with_password
from .kme import generate_managed_key, KeyStatus

class LifecycleState(Enum):
    ACTIVE = "ACTIVE"
    EXPIRED = "EXPIRED"
    ROTATED = "ROTATED"
    REVOKED = "REVOKED"
    COMPROMISED = "COMPROMISED"
    RETIRED = "RETIRED"

class KeyLifecycleManager:
    """Centralized orchestrator for Key Lifecycles."""
    def __init__(self, db_instance):
        self.db = db_instance

    def _log_usage(self, key_id: str, operation: str, status: str, category: str):
        """Audits cryptographic operations."""
        self.db.insert_lifecycle_audit(str(uuid.uuid4()), key_id, operation, status, category)

    def rotate_key(self, old_key_id: str) -> str:
        """
        Generates a new key of the same algorithm and purpose.
        Transitions the old key to 'ROTATED' but does not delete it (Historical Decryption).
        Links versions in the lifecycle_versions table.
        """
        old_meta = self.db.get_kms_key_metadata(old_key_id)
        if not old_meta:
            raise InvalidInputError("Old key not found in registry.")
            
        if old_meta["status"] in [LifecycleState.REVOKED.value, LifecycleState.COMPROMISED.value]:
            raise CryptographicOperationError("Cannot perform standard rotation on a Revoked/Compromised key. Use explicit replacement.")

        # 1. Generate Replacement
        new_id, raw_key, new_meta = generate_managed_key(
            algorithm=old_meta["algorithm"], 
            size=256, # Assuming standard 256-bit symmetric for this educational lab, or 3072 for RSA
            usage=old_meta["intended_usage"]
        )
        new_meta["associated_identity"] = old_meta["associated_identity"]
        new_meta["category"] = old_meta["category"]
        
        # 2. Register Replacement
        self.db.insert_kms_key(new_meta)
        
        # 3. Update Old Key Status
        self.db.update_kms_key_status(old_key_id, LifecycleState.ROTATED.value, rotated_to=new_id)
        
        # 4. Version Tracking (Parent -> Child)
        # Determine existing version number
        existing_versions = self.db.get_lifecycle_versions(old_key_id)
        current_v = existing_versions[0]["version_number"] if existing_versions else 1
        
        # Insert old version if it wasn't tracked yet (Retroactive migration)
        if not existing_versions:
            self.db.insert_lifecycle_version(old_key_id, None, 1)
            
        self.db.insert_lifecycle_version(new_id, old_key_id, current_v + 1)
        
        # 5. Audit
        self._log_usage(old_key_id, "ROTATE_OUT", "SUCCESS", "LIFECYCLE")
        self._log_usage(new_id, "ROTATE_IN", "SUCCESS", "LIFECYCLE")
        
        return new_id

    def revoke_key(self, key_id: str, reason: str, is_compromised: bool = False):
        """Revokes a key. Rejects future encryption, optionally warns on historical decryption."""
        status = LifecycleState.COMPROMISED.value if is_compromised else LifecycleState.REVOKED.value
        self.db.update_kms_key_status(key_id, status, revocation_reason=reason)
        self._log_usage(key_id, "REVOKE", "SUCCESS", "SECURITY")

    def simulate_compromise(self, key_id: str) -> Dict[str, Any]:
        """
        Educational PCS and Dependency Analysis.
        Explains blast radius of a compromised key based on its category.
        """
        meta = self.db.get_kms_key_metadata(key_id)
        if not meta: raise InvalidInputError("Key not found.")
        
        self.revoke_key(key_id, "Simulated Lab Compromise", is_compromised=True)
        
        impact = {
            "key_id": key_id,
            "category": meta["category"],
            "blast_radius": "",
            "required_action": ""
        }
        
        if meta["category"] == "Identity":
            impact["blast_radius"] = "All active E2EE Sessions and Ratchets utilizing this Identity are compromised. Attacker can impersonate this identity."
            impact["required_action"] = "Terminate all E2EE sessions. Issue new Identity Key. Re-establish out-of-band trust (QR Exchange)."
        elif meta["category"] == "Session":
            impact["blast_radius"] = "The specific E2EE session is compromised. Historical messages might be decrypted if Forward Secrecy (Ratchet) was not active."
            impact["required_action"] = "Terminate session immediately. Initiate new Authenticated Key Exchange (AKE)."
        else:
            impact["blast_radius"] = f"Any data encrypted statically with this {meta['algorithm']} key is exposed."
            impact["required_action"] = "Rotate key immediately. Re-encrypt sensitive records if possible."
            
        return impact

    def create_secure_backup(self, key_id: str, raw_key_material: bytes, backup_password: str) -> str:
        """
        Creates a versioned, AES-GCM + Argon2id encrypted backup envelope.
        Never stores the password or raw key.
        """
        meta = self.db.get_kms_key_metadata(key_id)
        if not meta: raise InvalidInputError("Key not found in registry.")
        
        payload_data = {
            "key_id": key_id,
            "algorithm": meta["algorithm"],
            "raw_material_b64": bytes_to_b64(raw_key_material),
            "intended_usage": meta["intended_usage"]
        }
        
        # We reuse the robust M14 PBE engine (Argon2id -> AES-GCM)
        encrypted_package = encrypt_with_password(backup_password, json.dumps(payload_data), "Argon2id")
        
        backup_id = f"BKP-{str(uuid.uuid4())[:8]}"
        self.db.insert_lifecycle_backup(backup_id, key_id, "V33.0", json.dumps(encrypted_package))
        
        self._log_usage(key_id, "BACKUP_CREATE", "SUCCESS", "LIFECYCLE")
        return backup_id

    def restore_backup(self, encrypted_package_json: str, backup_password: str) -> Dict[str, Any]:
        """Validates and restores a backed-up key into memory."""
        try:
            # Decrypt the package
            decrypted_text = decrypt_with_password(backup_password, encrypted_package_json)
            payload = json.loads(decrypted_text)
            
            # Reconstruct binary material safely
            payload["raw_material_bytes"] = b64_to_bytes(payload["raw_material_b64"])
            del payload["raw_material_b64"]
            
            self._log_usage(payload["key_id"], "BACKUP_RESTORE", "SUCCESS", "LIFECYCLE")
            return payload
            
        except Exception as e:
            raise AuthenticationError(f"Backup Restoration Failed. Incorrect Password or Tampered Backup. ({str(e)})")

class KeyDependencyAnalyzer:
    """M33: Identifies relationships between keys, identities, and sessions."""
    def __init__(self, db_instance):
        self.db = db_instance
        
    def analyze_identity_dependencies(self, identity_name: str) -> Dict[str, Any]:
        """Finds all sessions and keys tied to a user identity."""
        sessions = self.db.get_e2ee_sessions_by_identity(identity_name)
        keys = self.db.get_all_kms_keys()
        identity_keys = [k for k in keys if k.get("associated_identity") == identity_name]
        
        return {
            "identity": identity_name,
            "active_sessions_count": len([s for s in sessions if s["status"] == "ACTIVE"]),
            "total_sessions_affected": len(sessions),
            "linked_kms_keys": len(identity_keys)
        }
