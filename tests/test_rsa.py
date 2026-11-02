"""
Automated Testing for Milestone 5: Advanced RSA Asymmetric Cryptography Engine.
Ensures correct key serialization, encryption/decryption boundaries, and OAEP enforcement.
"""
import pytest
import json
from core.rsa import (
    generate_rsa_key_pair, serialize_private_key_pem, serialize_public_key_pem,
    load_private_key_pem, load_public_key_pem, generate_public_key_fingerprint,
    encrypt_rsa_oaep, decrypt_rsa_oaep, get_max_encryption_size
)
from core.exceptions import InvalidInputError, KeySerializationError, CryptographicOperationError

def test_rsa_key_generation_and_serialization():
    # Keep key size small for fast tests, 2048 is fine for unit testing.
    priv, pub = generate_rsa_key_pair(2048)
    
    password = "StrictlySecurePassword123!"
    
    priv_pem = serialize_private_key_pem(priv, password)
    pub_pem = serialize_public_key_pem(pub)
    
    assert "BEGIN ENCRYPTED PRIVATE KEY" in priv_pem
    assert "BEGIN PUBLIC KEY" in pub_pem
    
    # Reload Keys
    reloaded_priv = load_private_key_pem(priv_pem, password)
    reloaded_pub = load_public_key_pem(pub_pem)
    
    assert reloaded_priv.key_size == 2048
    assert reloaded_pub.key_size == 2048

def test_rsa_wrong_password_rejection():
    priv, _ = generate_rsa_key_pair(2048)
    priv_pem = serialize_private_key_pem(priv, "CorrectPassword")
    
    with pytest.raises(KeySerializationError):
        load_private_key_pem(priv_pem, "WrongPassword")

def test_rsa_oaep_round_trip():
    priv, pub = generate_rsa_key_pair(2048)
    message = "Highly confidential RSA-OAEP payload."
    
    payload = encrypt_rsa_oaep(pub, message)
    
    assert payload["version"] == 1
    assert payload["algorithm"] == "RSA-OAEP-SHA256"
    assert payload["key_size"] == 2048
    
    recovered = decrypt_rsa_oaep(priv, json.dumps(payload))
    assert recovered == message

def test_rsa_oversize_plaintext_rejection():
    _, pub = generate_rsa_key_pair(2048)
    max_size = get_max_encryption_size(2048)
    
    oversized_msg = "A" * (max_size + 1)
    
    with pytest.raises(InvalidInputError) as excinfo:
        encrypt_rsa_oaep(pub, oversized_msg)
    
    assert "too long" in str(excinfo.value)
    
    # Valid size should succeed
    exact_size_msg = "A" * max_size
    assert encrypt_rsa_oaep(pub, exact_size_msg) is not None

def test_rsa_fingerprint_consistency():
    _, pub = generate_rsa_key_pair(2048)
    
    fp1 = generate_public_key_fingerprint(pub)
    fp2 = generate_public_key_fingerprint(pub)
    
    assert fp1 == fp2
    assert len(fp1.split(":")) == 32 # SHA-256 is 32 bytes
