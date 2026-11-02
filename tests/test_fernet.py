"""
Automated Testing for Milestone 9: Advanced Fernet Symmetric Encryption Laboratory.
Ensures correct AES-CBC/HMAC wrapping, TTL enforcement, and MultiFernet Rotation.
"""
import pytest
import json
import time
from core.fernet_engine import (
    generate_fernet_key, validate_fernet_key, fingerprint_fernet_key,
    encrypt_fernet_text, decrypt_fernet_text, rotate_fernet_token, inspect_fernet_token
)
from core.exceptions import InvalidInputError, AuthenticationError

def test_fernet_key_generation_and_validation():
    key = generate_fernet_key()
    assert isinstance(key, str)
    # Validation will throw if invalid
    key_bytes = validate_fernet_key(key)
    assert len(key_bytes) == 44 # 32 bytes base64 encoded is 44 chars
    
    fp = fingerprint_fernet_key(key)
    assert len(fp.split(":")) == 32 # SHA-256

def test_fernet_round_trip():
    key = generate_fernet_key()
    message = "Fernet Authenticated Encryption Test ✅"
    
    payload = encrypt_fernet_text(key, message)
    assert payload["format_version"] == "1.0"
    assert payload["algorithm"] == "Fernet"
    
    recovered = decrypt_fernet_text(key, json.dumps(payload))
    assert recovered == message

def test_fernet_invalid_key():
    bad_key = "not_a_base64_key_that_is_32_bytes_long"
    with pytest.raises(InvalidInputError):
        encrypt_fernet_text(bad_key, "Test")

def test_fernet_authentication_tampering():
    key = generate_fernet_key()
    payload = encrypt_fernet_text(key, "Sensitive Data")
    
    # Tamper with token (even changing a single character breaks HMAC-SHA256)
    payload["token"] = payload["token"][:-2] + "AA"
    
    with pytest.raises(AuthenticationError):
        decrypt_fernet_text(key, json.dumps(payload))

def test_fernet_ttl_expiration():
    key = generate_fernet_key()
    payload = encrypt_fernet_text(key, "Time sensitive payload")
    
    # TTL of -1 enforces immediate expiration of any token
    with pytest.raises(AuthenticationError) as exc:
        decrypt_fernet_text(key, json.dumps(payload), ttl=-1)
    
    assert "expired" in str(exc.value).lower() or "invalid" in str(exc.value).lower()

def test_fernet_multifernet_rotation():
    old_key = generate_fernet_key()
    new_primary_key = generate_fernet_key()
    
    payload = encrypt_fernet_text(old_key, "Legacy Data")
    
    # Verify new key cannot decrypt it normally
    with pytest.raises(AuthenticationError):
        decrypt_fernet_text(new_primary_key, json.dumps(payload))
        
    # Rotate using MultiFernet
    rotated_payload = rotate_fernet_token(new_primary_key, [old_key], json.dumps(payload))
    
    # Verify the timestamp is preserved
    assert payload["created_at"] == rotated_payload["created_at"]
    
    # Verify new key CAN decrypt rotated payload natively
    recovered = decrypt_fernet_text(new_primary_key, json.dumps(rotated_payload))
    assert recovered == "Legacy Data"

def test_fernet_token_inspection():
    key = generate_fernet_key()
    payload = encrypt_fernet_text(key, "Inspector Test")
    
    metadata = inspect_fernet_token(payload["token"])
    assert metadata["timestamp"] == payload["created_at"]
    assert metadata["age_seconds"] >= 0
