"""
Automated Testing for Milestone 21: Advanced Secure File Encryption Laboratory.
Validates PBE File, Hybrid File, sanitization, and size limits.
"""
import pytest
import json
import io
from core.file_encryption import (
    encrypt_file_pbe, decrypt_file_pbe, encrypt_file_hybrid, decrypt_file_hybrid,
    sanitize_filename, MAX_FILE_SIZE
)
from core.rsa import generate_rsa_key_pair
from core.exceptions import InvalidInputError, AuthenticationError

@pytest.fixture(scope="module")
def rsa_keys():
    priv, pub = generate_rsa_key_pair(2048) # 2048 for faster testing
    return priv, pub

def test_filename_sanitization():
    assert sanitize_filename("../../../../etc/passwd") == "passwd"
    assert sanitize_filename("valid_image.png") == "valid_image.png"
    assert sanitize_filename("spaces and chars!@#.txt") == "spaces_and_chars____.txt"
    assert sanitize_filename("") == "unnamed_file.bin"

def test_pbe_file_roundtrip():
    password = "SecureFilePass"
    file_bytes = b"PDF_HEADER_SIMULATION\x00\x01\x02"
    filename = "report.pdf"
    
    pkg = encrypt_file_pbe(password, file_bytes, filename, kdf_algo="PBKDF2-HMAC-SHA256", kdf_params={"iterations": 10000})
    
    assert pkg["encryption_type"] == "PBE-File"
    assert pkg["original_filename"] == filename
    
    rec_filename, rec_bytes = decrypt_file_pbe(password, json.dumps(pkg))
    assert rec_filename == filename
    assert rec_bytes == file_bytes

def test_hybrid_file_roundtrip(rsa_keys):
    priv, pub = rsa_keys
    file_bytes = b"BINARY_IMAGE_DATA_SIMULATION"
    filename = "photo.jpg"
    
    pkg = encrypt_file_hybrid(pub, file_bytes, filename, cipher_algo="ChaCha20-Poly1305")
    
    assert pkg["encryption_type"] == "Hybrid-File"
    assert pkg["cipher"]["algorithm"] == "ChaCha20-Poly1305"
    
    rec_filename, rec_bytes = decrypt_file_hybrid(priv, json.dumps(pkg))
    assert rec_filename == filename
    assert rec_bytes == file_bytes

def test_file_size_limit():
    password = "Pass"
    # Create a dummy byte array that exceeds the max limit
    # We mock this constraint in the test to avoid allocating 51MB of RAM in CI
    large_data = b"A" * (MAX_FILE_SIZE + 1)
    
    with pytest.raises(InvalidInputError) as exc:
        encrypt_file_pbe(password, large_data, "large.bin")
    assert "exceeds maximum safe in-memory limit" in str(exc.value)

def test_tampered_file_metadata(rsa_keys):
    priv, pub = rsa_keys
    pkg = encrypt_file_hybrid(pub, b"Sensitive Data", "data.txt")
    
    # Attacker tries to rename the file after encryption
    pkg["original_filename"] = "malicious.exe"
    
    with pytest.raises(AuthenticationError):
        decrypt_file_hybrid(priv, json.dumps(pkg))
