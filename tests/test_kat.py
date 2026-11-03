"""
Cryptographic Known-Answer Tests (KAT) - M28.
Validates algorithms against strictly defined RFC/NIST test vectors.
"""
import pytest
from core.integrity import calculate_hash
from core.encoding import text_to_bytes, bytes_to_hex, hex_to_bytes, bytes_to_b64
from core.aes_gcm import encrypt_aes_gcm, decrypt_aes_gcm
from core.hmac_engine import calculate_hmac

def test_kat_sha256():
    # RFC 4634 / NIST FIPS 180-4 Test Vector for empty string
    empty_digest_hex = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    res_b64 = calculate_hash(b"", "SHA-256")
    import base64
    res_hex = bytes_to_hex(base64.b64decode(res_b64))
    assert res_hex == empty_digest_hex

def test_kat_hmac_sha256():
    # RFC 4231 Test Case 1
    key = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    data = b"Hi There"
    expected_mac = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
    
    mac_bytes = calculate_hmac(key, data, "HMAC-SHA256")
    assert bytes_to_hex(mac_bytes) == expected_mac
