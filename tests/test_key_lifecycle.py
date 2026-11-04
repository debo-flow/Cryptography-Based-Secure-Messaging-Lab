"""
Automated Testing for Milestone 33: Key Lifecycle Management.
Validates Key Rotation, Version Tracking, Revocation, Compromise Simulation, and Encrypted Backups.
"""
import pytest
import json
import os
from core.database import MetadataDatabase
from core.kme import generate_managed_key
from core.key_lifecycle import KeyLifecycleManager, KeyDependencyAnalyzer, LifecycleState
from core.exceptions import AuthenticationError, InvalidInputError

@pytest.fixture
def lifecycle_env():
    """Sets up an isolated in-memory DB and the Lifecycle Manager."""
    db = MetadataDatabase(":memory:")
    mgr = KeyLifecycleManager(db)
    analyzer = KeyDependencyAnalyzer(db)
    return db, mgr, analyzer

@pytest.fixture
def seed_key(lifecycle_env):
    """Generates a dummy AES key in the KMS registry."""
    db, mgr, _ = lifecycle_env
    kid, raw, meta = generate_managed_key("AES-256", 256, "General Encryption")
    meta["associated_identity"] = "Alice"
    db.insert_kms_key(meta)
    return kid, raw, meta

def test_key_rotation_and_versioning(lifecycle_env, seed_key):
    db, mgr, _ = lifecycle_env
    old_kid, _, _ = seed_key
    
    # Perform Rotation
    new_kid = mgr.rotate_key(old_kid)
    
    # 1. Verify old key status is ROTATED
    old_meta = db.get_kms_key_metadata(old_kid)
    assert old_meta["status"] == LifecycleState.ROTATED.value
    assert old_meta["rotated_to"] == new_kid
    
    # 2. Verify new key exists and is ACTIVE
    new_meta = db.get_kms_key_metadata(new_kid)
    assert new_meta["status"] == LifecycleState.ACTIVE.value
    
    # 3. Verify Version Tracking
    versions = db.get_lifecycle_versions(old_kid)
    assert len(versions) == 2
    assert versions[0]["key_id"] == new_kid # Newest first
    assert versions[0]["version_number"] == 2
    assert versions[1]["key_id"] == old_kid
    assert versions[1]["version_number"] == 1

def test_key_compromise_and_revocation(lifecycle_env, seed_key):
    db, mgr, _ = lifecycle_env
    kid, _, _ = seed_key
    
    impact = mgr.simulate_compromise(kid)
    assert impact["key_id"] == kid
    assert "blast_radius" in impact
    
    meta = db.get_kms_key_metadata(kid)
    assert meta["status"] == LifecycleState.COMPROMISED.value
    
    # Attempting to rotate a compromised key normally should fail (must be explicitly replaced)
    with pytest.raises(Exception) as exc:
        mgr.rotate_key(kid)
    assert "Cannot perform standard rotation" in str(exc.value)

def test_secure_backup_and_recovery(lifecycle_env, seed_key):
    db, mgr, _ = lifecycle_env
    kid, raw_material, _ = seed_key
    password = "StrongBackupPassword123!"
    
    # 1. Create Backup
    backup_id = mgr.create_secure_backup(kid, raw_material, password)
    backups = db.get_lifecycle_backups()
    assert len(backups) == 1
    assert backups[0]["backup_id"] == backup_id
    
    encrypted_payload = backups[0]["encrypted_payload"]
    
    # 2. Successful Recovery
    recovered = mgr.restore_backup(encrypted_payload, password)
    assert recovered["key_id"] == kid
    assert recovered["raw_material_bytes"] == raw_material
    
    # 3. Failed Recovery (Wrong Password)
    with pytest.raises(AuthenticationError):
        mgr.restore_backup(encrypted_payload, "WrongPassword!")

def test_dependency_analyzer(lifecycle_env):
    db, _, analyzer = lifecycle_env
    
    # Create fake session attached to Alice
    db.insert_e2ee_v2_session("SESS-999", "Alice", "Bob", "V2.0", "AES", 10.0, 20.0, "ACTIVE")
    
    deps = analyzer.analyze_identity_dependencies("Alice")
    assert deps["identity"] == "Alice"
    assert deps["total_sessions_affected"] == 1
