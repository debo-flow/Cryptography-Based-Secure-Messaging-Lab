"""
Automated Testing for Milestone 4: AES-GCM Encryption Engine.
Ensures correct AEAD implementation, AAD binding, and rigid tamper resistance.
"""
import pytest
import json
from core.aes_gcm import encrypt_aes_gcm, decrypt_aes_gcm
from core.randomness import generate_random_bytes
from core.exceptions import InvalidInputError, AuthenticationError
from core.encoding import bytes_to_b64, b64_to_bytes, bytes_to_text

@pytest.mark.parametrize("algorithm, key_size", [
    ("AES-128-GCM", 16),
    ("AES-192-GCM", 24),
    ("AES-256-GCM", 32)
])
def test_aes_gcm_round_trip(algorithm, key_size):
    key = generate_random_bytes(key_size)
    plaintext = "GCM AEAD Integration Test 🔐"
    aad = "MessageID: 99482"
    
    payload = encrypt_aes_gcm(key, plaintext, algorithm, aad)
    assert payload["version"] == 1
    assert payload["algorithm"] == algorithm
    
    # Decrypt and Verify
    recovered = decrypt_aes_gcm(key, json.dumps(payload))
    assert recovered == plaintext

def test_invalid_key_length():
    bad_key = generate_random_bytes(10)
    with pytest.raises(InvalidInputError):
        encrypt_aes_gcm(bad_key, "Test", "AES-256-GCM")

def test_authentication_failure_tampered_ciphertext():
    key = generate_random_bytes(32)
    payload = encrypt_aes_gcm(key, "Sensitive Data", "AES-256-GCM")
    
    # Tamper with ciphertext by modifying the base64 string
    payload["ciphertext"] = payload["ciphertext"][:-3] + "AAA"
    
    with pytest.raises(AuthenticationError):
        decrypt_aes_gcm(key, json.dumps(payload))

def test_authentication_failure_tampered_aad():
    key = generate_random_bytes(32)
    payload = encrypt_aes_gcm(key, "Sensitive Data", "AES-256-GCM", aad="User: Alice")
    
    # Modify AAD to Bob
    payload["aad"] = bytes_to_b64(b"User: Bob")
    
    with pytest.raises(AuthenticationError):
        decrypt_aes_gcm(key, json.dumps(payload))

def test_authentication_failure_wrong_key():
    key = generate_random_bytes(32)
    wrong_key = generate_random_bytes(32)
    
    payload = encrypt_aes_gcm(key, "Sensitive Data", "AES-256-GCM")
    
    with pytest.raises(AuthenticationError):
        decrypt_aes_gcm(wrong_key, json.dumps(payload))

def test_empty_messages_and_empty_aad():
    key = generate_random_bytes(32)
    
    empty_payload = encrypt_aes_gcm(key, "", "AES-256-GCM", "")
    assert decrypt_aes_gcm(key, json.dumps(empty_payload)) == ""
