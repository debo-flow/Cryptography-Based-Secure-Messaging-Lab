"""
Automated Testing for Milestone 2: Cryptographic Core Engine.
Validates randomness, encoding, exceptions, and DB schemas.
"""
import pytest
import os
from core.randomness import generate_random_bytes, generate_random_token, generate_salt
from core.encoding import (
    text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes, bytes_to_hex, hex_to_bytes
)
from core.validation import validate_length, validate_positive_integer
from core.exceptions import InvalidInputError, EncodingError
from core.database import MetadataDatabase
from core.metadata import KeyMetadata, KeyStatus

def test_randomness_generation():
    """Test CSPRNG implementations."""
    b1 = generate_random_bytes(16)
    b2 = generate_random_bytes(16)
    assert len(b1) == 16
    assert b1 != b2  # Cryptographic guarantee against collision on immediate calls
    
    t1 = generate_random_token(32)
    assert isinstance(t1, str)
    assert len(t1) > 0

    with pytest.raises(InvalidInputError):
        generate_random_bytes(0)
    with pytest.raises(InvalidInputError):
        generate_random_bytes(-5)

def test_encoding_utilities():
    """Test text/bytes/b64/hex conversions."""
    test_string = "SecureLab_2026! 🔐"
    
    raw = text_to_bytes(test_string)
    assert isinstance(raw, bytes)
    assert bytes_to_text(raw) == test_string
    
    b64 = bytes_to_b64(raw)
    assert isinstance(b64, str)
    assert b64_to_bytes(b64) == raw
    
    hex_str = bytes_to_hex(raw)
    assert isinstance(hex_str, str)
    assert hex_to_bytes(hex_str) == raw

def test_encoding_exceptions():
    """Test that invalid conversions fail securely."""
    with pytest.raises(EncodingError):
        b64_to_bytes("Invalid_!@#_B64")
    
    with pytest.raises(EncodingError):
        hex_to_bytes("not_a_hex_string")

def test_metadata_database():
    """Test SQLite initialization and parameterization."""
    test_db_path = "test_metadata.db"
    if os.path.exists(test_db_path):
        os.remove(test_db_path)
        
    db = MetadataDatabase(db_path=test_db_path)
    
    # Test Key Metadata Insertion and Retrieval
    km = KeyMetadata(
        key_id="key-12345",
        algorithm="AES-256-GCM",
        purpose="FileEncryption",
        status=KeyStatus.ACTIVE,
        version=1
    )
    
    db.insert_key_metadata(km)
    fetched_km = db.get_key_metadata("key-12345")
    
    assert fetched_km is not None
    assert fetched_km.algorithm == "AES-256-GCM"
    assert fetched_km.status == KeyStatus.ACTIVE
    
    # Cleanup
    os.remove(test_db_path)
