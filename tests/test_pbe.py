"""
Automated Testing for Milestone 13: Password-Based Encryption (PBE).
Ensures KDF iteration limits, deterministic AAD binding, and secure authentication rejections.
"""
import pytest
import json
from core.pbe import (
    derive_encryption_key, generate_pbe_salt, encrypt_with_password, decrypt_with_password,
    PBE_KEY_SIZE, PBE_SALT_SIZE
)
from core.exceptions import InvalidInputError, CryptographicOperationError, AuthenticationError
from core.encoding import bytes_to_b64, b64_to_bytes

def test_pbe_key_derivation_consistency():
    password = "SuperSecretPassword123!"
    salt = generate_pbe_salt()
    iters = 50_000
    
    key1 = derive_encryption_key(password, salt, iters)
    key2 = derive_encryption_key(password, salt, iters)
    
    assert key1 == key2
    assert len(key1) == PBE_KEY_SIZE

def test_pbe_round_trip():
    password = "StrongPassword456"
    message = "Highly confidential PBE payload containing Unicode 🔐"
    
    payload = encrypt_with_password(password, message, iterations=15_000)
    
    assert payload["format_version"] == "1.0"
    assert payload["encryption_type"] == "Password-Based Encryption"
    assert "salt" in payload["kdf"]
    
    recovered = decrypt_with_password(password, json.dumps(payload))
    assert recovered == message

def test_pbe_wrong_password_rejection():
    payload = encrypt_with_password("CorrectPass", "Data", iterations=15_000)
    
    with pytest.raises(AuthenticationError) as exc:
        decrypt_with_password("WrongPass", json.dumps(payload))
    assert "Authentication failed" in str(exc.value)

def test_pbe_tampered_ciphertext():
    payload = encrypt_with_password("MyPass", "Sensitive Data", iterations=15_000)
    
    ct_bytes = b64_to_bytes(payload["ciphertext"])
    tampered_ct = bytes([ct_bytes[0] ^ 0xFF]) + ct_bytes[1:]
    payload["ciphertext"] = bytes_to_b64(tampered_ct)
    
    with pytest.raises(AuthenticationError):
        decrypt_with_password("MyPass", json.dumps(payload))

def test_pbe_tampered_metadata():
    """Proves that tampering with the iteration count or salt strictly fails decryption due to AAD/KDF mismatch."""
    payload = encrypt_with_password("MyPass", "Sensitive Data", iterations=15_000)
    
    # Attacker tries to alter iteration count to cause a DoS or trick the decoder
    payload["kdf"]["iterations"] = 100_000
    
    with pytest.raises(AuthenticationError):
        decrypt_with_password("MyPass", json.dumps(payload))

def test_pbe_iteration_bounds():
    salt = generate_pbe_salt()
    
    # Too low
    with pytest.raises(InvalidInputError):
        derive_encryption_key("Pass", salt, iterations=5000)
        
    # Too high
    with pytest.raises(InvalidInputError):
        derive_encryption_key("Pass", salt, iterations=10_000_000)

def test_pbe_empty_and_large_messages():
    passw = "Admin"
    
    # Empty
    empty_payload = encrypt_with_password(passw, "", iterations=15_000)
    assert decrypt_with_password(passw, json.dumps(empty_payload)) == ""
    
    # Large
    large_msg = "A" * 100000 
    large_payload = encrypt_with_password(passw, large_msg, iterations=15_000)
    assert decrypt_with_password(passw, json.dumps(large_payload)) == large_msg
