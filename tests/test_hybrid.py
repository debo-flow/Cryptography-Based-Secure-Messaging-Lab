"""
Automated Testing for Milestone 10: Advanced Hybrid Encryption Laboratory.
Validates RSA DEK wrapping, AES-GCM bulk encryption, and structural tamper-resistance.
"""
import pytest
import json
from core.hybrid import encrypt_hybrid_message, decrypt_hybrid_message
from core.rsa import generate_rsa_key_pair
from core.exceptions import CryptographicOperationError, AuthenticationError, InvalidInputError
from core.encoding import bytes_to_b64, b64_to_bytes

@pytest.fixture(scope="module")
def rsa_keys():
    # 2048-bit used for test speed. Production uses 3072+.
    priv, pub = generate_rsa_key_pair(2048)
    return priv, pub

def test_hybrid_round_trip(rsa_keys):
    priv, pub = rsa_keys
    message = "Highly confidential hybrid payload containing UTF-8! 🔐"
    
    payload = encrypt_hybrid_message(pub, message)
    
    assert payload["format_version"] == "1.0"
    assert payload["encryption_scheme"] == "RSA-OAEP-SHA256+AES-256-GCM"
    assert "wrapped_dek" in payload["key_wrapping"]
    assert "ciphertext" in payload["content_encryption"]
    
    recovered = decrypt_hybrid_message(priv, json.dumps(payload))
    assert recovered == message

def test_hybrid_wrong_private_key(rsa_keys):
    _, pub = rsa_keys
    wrong_priv, _ = generate_rsa_key_pair(2048)
    
    payload = encrypt_hybrid_message(pub, "Data")
    
    with pytest.raises(CryptographicOperationError) as exc:
        decrypt_hybrid_message(wrong_priv, json.dumps(payload))
    assert "Unwrapping failed" in str(exc.value)

def test_hybrid_tampered_ciphertext(rsa_keys):
    priv, pub = rsa_keys
    payload = encrypt_hybrid_message(pub, "Sensitive Data")
    
    # Modify AES-GCM ciphertext
    ct_bytes = b64_to_bytes(payload["content_encryption"]["ciphertext"])
    tampered_ct = bytes([ct_bytes[0] ^ 0xFF]) + ct_bytes[1:]
    payload["content_encryption"]["ciphertext"] = bytes_to_b64(tampered_ct)
    
    with pytest.raises(AuthenticationError):
        decrypt_hybrid_message(priv, json.dumps(payload))

def test_hybrid_tampered_metadata(rsa_keys):
    """Proves AAD binding prevents metadata manipulation."""
    priv, pub = rsa_keys
    payload = encrypt_hybrid_message(pub, "Sensitive Data")
    
    # Attacker tries to alter the reported fingerprint in the JSON
    payload["key_wrapping"]["recipient_key_fingerprint"] = "FAKE_FINGERPRINT_123"
    
    with pytest.raises(AuthenticationError):
        decrypt_hybrid_message(priv, json.dumps(payload))

def test_hybrid_empty_and_large_messages(rsa_keys):
    priv, pub = rsa_keys
    
    # Empty
    empty_payload = encrypt_hybrid_message(pub, "")
    assert decrypt_hybrid_message(priv, json.dumps(empty_payload)) == ""
    
    # Large
    large_msg = "A" * 100000 
    large_payload = encrypt_hybrid_message(pub, large_msg)
    assert decrypt_hybrid_message(priv, json.dumps(large_payload)) == large_msg
