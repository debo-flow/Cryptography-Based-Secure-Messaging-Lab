"""
Automated Testing for Milestone 15: Advanced Digital Signature System.
Validates RSA-PSS, ECDSA, and Ed25519 generation, signing, tampering, and structural validation.
"""
import pytest
import json
from core.signatures import create_signature_package, validate_signature_package
from core.rsa import generate_rsa_key_pair
from core.ecc import generate_ecc_key_pair
from core.ed25519 import generate_ed25519_key_pair
from core.exceptions import InvalidInputError, AuthenticationError
from core.encoding import bytes_to_b64, b64_to_bytes, text_to_bytes

@pytest.fixture(scope="module")
def keys():
    rsa_priv, rsa_pub = generate_rsa_key_pair(2048)
    ecc_priv, ecc_pub = generate_ecc_key_pair("SECP256R1")
    ed_priv, ed_pub = generate_ed25519_key_pair()
    return {
        "rsa": (rsa_priv, rsa_pub),
        "ecc": (ecc_priv, ecc_pub),
        "ed": (ed_priv, ed_pub)
    }

def test_rsa_pss_signature_round_trip(keys):
    priv, pub = keys["rsa"]
    msg = "Approve RSA transfer."
    pkg = create_signature_package(priv, msg, "RSA-PSS-SHA256")
    
    assert pkg["algorithm"] == "RSA-PSS-SHA256"
    assert validate_signature_package(pub, json.dumps(pkg)) == msg

def test_ecdsa_signature_round_trip(keys):
    priv, pub = keys["ecc"]
    msg = "Approve ECDSA transfer."
    pkg = create_signature_package(priv, msg, "ECDSA-SECP256R1-SHA256")
    
    assert pkg["algorithm"] == "ECDSA-SECP256R1-SHA256"
    assert validate_signature_package(pub, json.dumps(pkg)) == msg

def test_ed25519_signature_round_trip(keys):
    priv, pub = keys["ed"]
    msg = "Approve Ed25519 transfer."
    pkg = create_signature_package(priv, msg, "Ed25519")
    
    assert pkg["algorithm"] == "Ed25519"
    assert validate_signature_package(pub, json.dumps(pkg)) == msg

def test_tampered_message_rejection(keys):
    priv, pub = keys["ed"]
    pkg = create_signature_package(priv, "Pay Alice $10", "Ed25519")
    
    # Tamper with the base64 message
    pkg["message"] = bytes_to_b64(text_to_bytes("Pay Alice $90"))
    
    with pytest.raises(AuthenticationError):
        validate_signature_package(pub, json.dumps(pkg))

def test_tampered_signature_rejection(keys):
    priv, pub = keys["rsa"]
    pkg = create_signature_package(priv, "Valid data", "RSA-PSS-SHA256")
    
    # Tamper with signature
    sig_bytes = b64_to_bytes(pkg["signature"])
    tampered_sig = bytes([sig_bytes[0] ^ 0xFF]) + sig_bytes[1:]
    pkg["signature"] = bytes_to_b64(tampered_sig)
    
    with pytest.raises(AuthenticationError):
        validate_signature_package(pub, json.dumps(pkg))

def test_wrong_public_key_rejection(keys):
    priv1, pub1 = keys["ed"]
    _, pub2 = generate_ed25519_key_pair() # Unrelated key
    
    pkg = create_signature_package(priv1, "Test Message", "Ed25519")
    
    with pytest.raises(AuthenticationError) as exc:
        validate_signature_package(pub2, json.dumps(pkg))
    assert "Key mismatch" in str(exc.value)
