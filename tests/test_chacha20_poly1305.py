"""
Automated Testing for Milestone 8: ChaCha20-Poly1305 Authenticated Encryption Engine.
Ensures correct AEAD implementation, AAD binding, and rigid tamper resistance.
"""
import pytest
import json
from core.chacha20_poly1305 import (
    generate_chacha20_poly1305_key, generate_chacha20_poly1305_nonce, 
    encrypt_chacha20_poly1305, decrypt_chacha20_poly1305,
    CHACHA20_POLY1305_KEY_SIZE, CHACHA20_POLY1305_NONCE_SIZE
)
from core.exceptions import InvalidInputError, AuthenticationError
from core.encoding import bytes_to_b64, b64_to_bytes

def test_chacha20_poly1305_key_and_nonce_generation():
    key = generate_chacha20_poly1305_key()
    nonce = generate_chacha20_poly1305_nonce()
    assert len(key) == CHACHA20_POLY1305_KEY_SIZE
    assert len(nonce) == CHACHA20_POLY1305_NONCE_SIZE

def test_chacha20_poly1305_round_trip():
    key = generate_chacha20_poly1305_key()
    plaintext = "ChaCha20-Poly1305 AEAD Integration Test 🔐"
    aad = "MessageID: 55412"
    
    payload = encrypt_chacha20_poly1305(key, plaintext, aad)
    assert payload["format_version"] == "1.0"
    assert payload["algorithm"] == "ChaCha20-Poly1305"
    
    recovered = decrypt_chacha20_poly1305(key, json.dumps(payload))
    assert recovered == plaintext

def test_invalid_key_length():
    bad_key = b"short_key"
    with pytest.raises(InvalidInputError):
        encrypt_chacha20_poly1305(bad_key, "Test")

def test_authentication_failure_tampered_ciphertext():
    key = generate_chacha20_poly1305_key()
    payload = encrypt_chacha20_poly1305(key, "Sensitive Data")
    
    ct_bytes = b64_to_bytes(payload["ciphertext"])
    tampered_ct = bytes([ct_bytes[0] ^ 0xFF]) + ct_bytes[1:]
    payload["ciphertext"] = bytes_to_b64(tampered_ct)
    
    with pytest.raises(AuthenticationError):
        decrypt_chacha20_poly1305(key, json.dumps(payload))

def test_authentication_failure_tampered_aad():
    key = generate_chacha20_poly1305_key()
    payload = encrypt_chacha20_poly1305(key, "Sensitive Data", "User: Alice")
    
    payload["aad"] = bytes_to_b64(b"User: Bob")
    
    with pytest.raises(AuthenticationError):
        decrypt_chacha20_poly1305(key, json.dumps(payload))

def test_authentication_failure_wrong_key():
    key = generate_chacha20_poly1305_key()
    wrong_key = generate_chacha20_poly1305_key()
    
    payload = encrypt_chacha20_poly1305(key, "Sensitive Data")
    
    with pytest.raises(AuthenticationError):
        decrypt_chacha20_poly1305(wrong_key, json.dumps(payload))

def test_empty_messages_and_empty_aad():
    key = generate_chacha20_poly1305_key()
    
    empty_payload = encrypt_chacha20_poly1305(key, "", "")
    assert decrypt_chacha20_poly1305(key, json.dumps(empty_payload)) == ""

def test_large_message():
    key = generate_chacha20_poly1305_key()
    large_msg = "A" * 100000
    large_payload = encrypt_chacha20_poly1305(key, large_msg)
    assert decrypt_chacha20_poly1305(key, json.dumps(large_payload)) == large_msg
