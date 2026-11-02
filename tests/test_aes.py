"""
Automated Testing for Milestone 3: AES Encryption Engine.
Ensures correctness, Encrypt-then-MAC enforcement, and tamper resistance.
"""
import pytest
import json
from core.aes import encrypt_aes, decrypt_aes, derive_keys
from core.randomness import generate_random_bytes
from core.exceptions import InvalidInputError, AuthenticationError, CryptographicOperationError
from core.encoding import bytes_to_b64

def test_key_derivation():
    master = generate_random_bytes(32)
    enc, mac = derive_keys(master, 32)
    assert len(enc) == 32
    assert len(mac) == 32
    assert enc != mac
    assert enc != master

@pytest.mark.parametrize("algorithm, key_size", [
    ("AES-128", 16),
    ("AES-192", 24),
    ("AES-256", 32)
])
def test_aes_round_trip(algorithm, key_size):
    master_key = generate_random_bytes(key_size)
    plaintext = "Secure Messaging Lab 🔐 - Integration Test 123"
    
    payload = encrypt_aes(master_key, plaintext, algorithm)
    assert payload["version"] == 1
    assert algorithm in payload["algorithm"]
    
    recovered = decrypt_aes(master_key, json.dumps(payload))
    assert recovered == plaintext

def test_invalid_key_length():
    bad_key = generate_random_bytes(10)
    with pytest.raises(InvalidInputError):
        encrypt_aes(bad_key, "Test", "AES-256")

def test_authentication_failure_tampered_ciphertext():
    master_key = generate_random_bytes(32)
    payload = encrypt_aes(master_key, "Sensitive Data", "AES-256")
    
    # Tamper with ciphertext by modifying the base64 string
    payload["ciphertext"] = payload["ciphertext"][:-2] + "AA"
    
    with pytest.raises(AuthenticationError):
        decrypt_aes(master_key, json.dumps(payload))

def test_authentication_failure_wrong_key():
    master_key = generate_random_bytes(32)
    wrong_key = generate_random_bytes(32)
    
    payload = encrypt_aes(master_key, "Sensitive Data", "AES-256")
    
    with pytest.raises(AuthenticationError):
        decrypt_aes(wrong_key, json.dumps(payload))

def test_empty_and_long_messages():
    master_key = generate_random_bytes(32)
    
    empty_payload = encrypt_aes(master_key, "", "AES-256")
    assert decrypt_aes(master_key, json.dumps(empty_payload)) == ""
    
    long_msg = "A" * 10000
    long_payload = encrypt_aes(master_key, long_msg, "AES-256")
    assert decrypt_aes(master_key, json.dumps(long_payload)) == long_msg
