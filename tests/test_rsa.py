"""
Automated Testing for Milestone 6: Advanced RSA-OAEP Encryption & Interoperability.
Ensures correct key serialization, dynamic parameter bindings, label validations, and strict length enforcement.
"""
import pytest
import json
from core.rsa import (
    generate_rsa_key_pair, encrypt_rsa_oaep, decrypt_rsa_oaep, get_max_encryption_size, SUPPORTED_DIGESTS
)
from core.exceptions import InvalidInputError, CryptographicOperationError, AuthenticationError
from core.encoding import bytes_to_b64

@pytest.mark.parametrize("digest", ["SHA256", "SHA384", "SHA512"])
def test_rsa_oaep_matrix_round_trip(digest):
    """Tests cross-compatibility of OAEP with various secure digest algorithms."""
    priv, pub = generate_rsa_key_pair(2048)
    message = f"Highly confidential RSA-OAEP payload using {digest}."
    
    payload = encrypt_rsa_oaep(pub, message, digest_name=digest)
    
    assert payload["version"] == 2
    assert payload["oaep_digest"] == digest
    assert payload["mgf_digest"] == digest
    
    recovered = decrypt_rsa_oaep(priv, json.dumps(payload))
    assert recovered == message

def test_rsa_oaep_label_validation():
    """Validates that OAEP correctly incorporates and strictly enforces mathematical labels."""
    priv, pub = generate_rsa_key_pair(2048)
    msg = "Label Test Payload"
    valid_label = "Connection-ID-5928"
    wrong_label = "Connection-ID-9999"
    
    # Encrypt with valid label
    payload = encrypt_rsa_oaep(pub, msg, "SHA256", valid_label)
    
    # Ensure decryption works when label matches
    assert decrypt_rsa_oaep(priv, json.dumps(payload), valid_label) == msg
    
    # Ensure decryption fails if user provides wrong label out of band
    with pytest.raises(AuthenticationError):
        decrypt_rsa_oaep(priv, json.dumps(payload), wrong_label)

def test_rsa_oversize_plaintext_rejection_matrix():
    """Ensures that dynamic calculation of modulus vs. hash block length is respected."""
    _, pub = generate_rsa_key_pair(2048)
    
    # Test across all digests
    for digest in SUPPORTED_DIGESTS.keys():
        max_size = get_max_encryption_size(2048, digest)
        oversized_msg = "A" * (max_size + 1)
        
        with pytest.raises(InvalidInputError) as excinfo:
            encrypt_rsa_oaep(pub, oversized_msg, digest)
        
        assert "too long" in str(excinfo.value)
        
        # Valid size should succeed
        exact_size_msg = "A" * max_size
        assert encrypt_rsa_oaep(pub, exact_size_msg, digest) is not None

def test_rsa_ciphertext_length_validation():
    """Ensures structurally malformed ciphertexts are rejected before math operations occur."""
    priv, pub = generate_rsa_key_pair(2048)
    payload = encrypt_rsa_oaep(pub, "Data")
    
    # RSA-2048 ciphertext MUST be exactly 256 bytes.
    # Tampering base64 to change byte length:
    payload["ciphertext"] = payload["ciphertext"][:-2]
    
    with pytest.raises(InvalidInputError) as excinfo:
        decrypt_rsa_oaep(priv, json.dumps(payload))
        
    assert "Ciphertext length" in str(excinfo.value)
