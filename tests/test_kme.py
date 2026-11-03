"""
Automated Testing for Milestone 22: Advanced Cryptographic Key Management System (KMS/KME).
Validates generation, encrypted storage at rest, metadata validation, and backup systems.
"""
import pytest
import json
from core.kme import (
    generate_managed_key, encrypt_key_for_storage, decrypt_key_from_storage,
    create_backup_package, restore_backup_package, KeyStatus, KeyCategory
)
from core.exceptions import InvalidInputError, AuthenticationError

def test_kme_generation_and_storage_roundtrip():
    password = "SuperSecureKMEPassword123"
    
    # 1. Generate Key
    key_id, raw_key, meta = generate_managed_key("AES-256", 256, "Database Encryption", "SysAdmin")
    
    assert meta["status"] == KeyStatus.GENERATED.value
    assert meta["category"] == KeyCategory.SYMMETRIC.value
    assert isinstance(raw_key, bytes)
    assert len(raw_key) == 32
    
    # 2. Encrypt for Storage
    storage_json = encrypt_key_for_storage(key_id, raw_key, meta["category"], password)
    pkg = json.loads(storage_json)
    
    assert pkg["format_version"] == "1.0"
    assert pkg["kdf"]["algorithm"] == "Argon2id"
    
    # 3. Decrypt and Verify
    recovered_key = decrypt_key_from_storage(storage_json, meta["algorithm"], meta["category"], password)
    assert recovered_key == raw_key

def test_kme_wrong_password_rejection():
    key_id, raw_key, meta = generate_managed_key("Ed25519", None, "Identity Signing")
    storage_json = encrypt_key_for_storage(key_id, raw_key, meta["category"], "CorrectPass")
    
    with pytest.raises(AuthenticationError) as exc:
        decrypt_key_from_storage(storage_json, meta["algorithm"], meta["category"], "WrongPass")
    assert "Invalid password" in str(exc.value)

def test_kme_tampered_storage_rejection():
    key_id, raw_key, meta = generate_managed_key("AES-128", 128, "Temp")
    storage_json = encrypt_key_for_storage(key_id, raw_key, meta["category"], "Pass")
    
    pkg = json.loads(storage_json)
    from core.encoding import b64_to_bytes, bytes_to_b64
    blob = b64_to_bytes(pkg["encrypted_blob"])
    tampered = bytes([blob[0] ^ 0xFF]) + blob[1:]
    pkg["encrypted_blob"] = bytes_to_b64(tampered)
    
    with pytest.raises(AuthenticationError):
        decrypt_key_from_storage(json.dumps(pkg), meta["algorithm"], meta["category"], "Pass")

def test_kme_backup_and_recovery():
    password = "BackupPassword999"
    mock_meta = [{"key_id": "123", "status": "ACTIVE"}]
    mock_storage = [{"key_id": "123", "encrypted_blob": "..."}]
    
    backup_json = create_backup_package(mock_meta, mock_storage, password)
    
    recovered = restore_backup_package(backup_json, password)
    assert recovered["metadata"][0]["key_id"] == "123"
    
    with pytest.raises(AuthenticationError):
        restore_backup_package(backup_json, "WrongBackupPass")
