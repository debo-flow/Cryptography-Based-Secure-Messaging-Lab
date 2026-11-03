"""
Automated Testing for Milestone 23: Advanced QR-Based Public-Key Exchange.
Validates QR generation, deterministic JSON signing, decoding, and tampering resistance.
"""
import pytest
import json
from core.qr_exchange import (
    create_qr_payload, sign_qr_payload, generate_qr_image, 
    decode_qr_image, verify_qr_payload
)
from core.ed25519 import generate_ed25519_key_pair
from core.exceptions import InvalidInputError, AuthenticationError

@pytest.fixture(scope="module")
def identity_keys():
    return generate_ed25519_key_pair()

def test_qr_payload_generation_and_signing(identity_keys):
    priv, pub = identity_keys
    
    payload = create_qr_payload("Alice-ID", pub)
    assert payload["identity_id"] == "Alice-ID"
    assert payload["algorithm"] == "Ed25519"
    assert "signature" not in payload
    
    signed_payload = sign_qr_payload(payload, priv)
    assert "signature" in signed_payload
    
    # Ensure verification passes
    verified_pkg, recovered_pub = verify_qr_payload(json.dumps(signed_payload))
    assert verified_pkg["fingerprint"] == payload["fingerprint"]

def test_qr_image_generation_and_decoding(identity_keys):
    priv, pub = identity_keys
    payload = create_qr_payload("Bob-ID", pub)
    
    # 1. Generate PNG
    png_bytes = generate_qr_image(payload)
    assert len(png_bytes) > 0
    assert png_bytes.startswith(b"\x89PNG")
    
    # 2. Decode PNG via OpenCV
    decoded_json = decode_qr_image(png_bytes)
    
    # 3. Verify
    verified_pkg, _ = verify_qr_payload(decoded_json)
    assert verified_pkg["identity_id"] == "Bob-ID"

def test_tampered_qr_fingerprint(identity_keys):
    _, pub = identity_keys
    payload = create_qr_payload("Charlie-ID", pub)
    
    # Attack: Tamper with the declared fingerprint
    payload["fingerprint"] = "FAKE-FINGERPRINT-12345"
    
    with pytest.raises(AuthenticationError) as exc:
        verify_qr_payload(json.dumps(payload))
    assert "FINGERPRINT MISMATCH" in str(exc.value)

def test_tampered_qr_signature(identity_keys):
    priv, pub = identity_keys
    payload = create_qr_payload("Dave-ID", pub)
    signed_payload = sign_qr_payload(payload, priv)
    
    # Attack: Alter the identity string after it was signed
    signed_payload["identity_id"] = "Eve-ID"
    
    with pytest.raises(AuthenticationError) as exc:
        verify_qr_payload(json.dumps(signed_payload))
    assert "Invalid QR Signature" in str(exc.value)
