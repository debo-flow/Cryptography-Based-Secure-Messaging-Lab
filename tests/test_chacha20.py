"""
Automated Testing for Milestone 7: ChaCha20 Stream Cipher Engine.
"""
import pytest
import json
from core.chacha20 import (
    generate_chacha20_key, generate_chacha20_nonce, encrypt_chacha20, decrypt_chacha20,
    CHACHA20_KEY_SIZE, CHACHA20_NONCE_SIZE
)
from core.exceptions import InvalidInputError, CryptographicOperationError
from core.encoding import bytes_to_b64, b64_to_bytes

def test_chacha20_key_and_nonce_generation():
    key = generate_chacha20_key()
    nonce = generate_chacha20_nonce()
    assert len(key) == CHACHA20_KEY_SIZE
    assert len(nonce) == CHACHA20_NONCE_SIZE

def test_chacha20_round_trip():
    key = generate_chacha20_key()
    message = "Stream Cipher Integration Test! 🌊"
    
    payload = encrypt_chacha20(key, message)
    assert payload["format_version"] == "1.0"
    assert payload["algorithm"] == "ChaCha20"
    
    recovered = decrypt_chacha20(key, json.dumps(payload))
    assert recovered == message

def test_invalid_key_length():
    bad_key = b"short_key"
    with pytest.raises(InvalidInputError):
        encrypt_chacha20(bad_key, "Test message")

def test_empty_and_large_messages():
    key = generate_chacha20_key()
    
    # Empty
    empty_payload = encrypt_chacha20(key, "")
    assert decrypt_chacha20(key, json.dumps(empty_payload)) == ""
    
    # Large
    large_msg = "A" * 100000
    large_payload = encrypt_chacha20(key, large_msg)
    assert decrypt_chacha20(key, json.dumps(large_payload)) == large_msg

def test_tampering_behavior_utf8_failure():
    """
    Demonstrates the DANGER of raw ChaCha20. 
    Bit flipping modifies the ciphertext. Because there is no MAC, 
    the engine attempts to decode the modified XOR output as UTF-8, which usually fails.
    """
    key = generate_chacha20_key()
    payload = encrypt_chacha20(key, "Sensitive Financial Data: $10000")
    
    ct_bytes = b64_to_bytes(payload["ciphertext"])
    # Tamper with the first byte
    tampered_ct = bytes([ct_bytes[0] ^ 0xFF]) + ct_bytes[1:]
    payload["ciphertext"] = bytes_to_b64(tampered_ct)
    
    with pytest.raises(CryptographicOperationError) as exc:
        decrypt_chacha20(key, json.dumps(payload))
        
    assert "invalid UTF-8 data" in str(exc.value)

def test_ciphertext_length_preservation():
    """Stream ciphers do not use padding. Ciphertext length must equal plaintext length."""
    key = generate_chacha20_key()
    msg = "Exact length"
    
    payload = encrypt_chacha20(key, msg)
    ct_bytes = b64_to_bytes(payload["ciphertext"])
    
    assert len(ct_bytes) == len(msg.encode('utf-8'))
