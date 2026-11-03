"""
Property-Based Testing & Fuzzing (M28).
Uses Hypothesis to generate dynamic bounds, testing Unicode edge cases and structural fuzzing.
"""
from hypothesis import given, strategies as st
import json
from core.aes_gcm import encrypt_aes_gcm, decrypt_aes_gcm
from core.randomness import generate_random_bytes
from core.exceptions import AuthenticationError, InvalidInputError

@given(st.text(min_size=1, max_size=1000), st.text(max_size=100))
def test_fuzz_aes_gcm_roundtrip(plaintext, aad):
    """Proves that ALL valid unicode strings strictly round-trip through AEAD."""
    key = generate_random_bytes(32)
    pkg = encrypt_aes_gcm(key, plaintext, "AES-256-GCM", aad)
    
    recovered = decrypt_aes_gcm(key, json.dumps(pkg))
    assert recovered == plaintext

@given(st.binary(min_size=32, max_size=32), st.text(min_size=1))
def test_fuzz_malformed_json_rejection(key, bad_json):
    """Negative Testing: Ensures the parser safely handles malformed JSON without crashing."""
    try:
        decrypt_aes_gcm(key, bad_json)
        assert False, "Should have thrown an error."
    except InvalidInputError:
        pass # Expected safe rejection

@given(st.text(min_size=1), st.text(min_size=1))
def test_fuzz_aead_aad_tampering(plaintext, fake_aad):
    """Proves that changing the AAD string strictly causes AuthenticationError."""
    key = generate_random_bytes(32)
    pkg = encrypt_aes_gcm(key, plaintext, "AES-256-GCM", "Real AAD")
    
    if fake_aad != "Real AAD":
        pkg["aad"] = fake_aad
        try:
            decrypt_aes_gcm(key, json.dumps(pkg))
            assert False, "Tampered AAD bypassed verification!"
        except AuthenticationError:
            pass # Expected
