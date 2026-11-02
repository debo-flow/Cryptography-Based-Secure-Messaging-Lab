"""
Automated Testing for Milestone 14: Advanced Key Derivation Function (KDF) Engine.
"""
import pytest
from core.kdf_engine import derive_key, generate_kdf_salt, KDF_DERIVED_KEY_LENGTH
from core.exceptions import InvalidInputError, CryptographicOperationError

def test_pbkdf2_derivation():
    salt = generate_kdf_salt()
    key = derive_key("Password123!", salt, "PBKDF2-HMAC-SHA256", {"iterations": 50_000})
    assert len(key) == KDF_DERIVED_KEY_LENGTH

def test_scrypt_derivation():
    salt = generate_kdf_salt()
    key = derive_key("Password123!", salt, "Scrypt", {"n": 1024, "r": 8, "p": 1})
    assert len(key) == KDF_DERIVED_KEY_LENGTH

def test_argon2id_derivation():
    salt = generate_kdf_salt()
    key = derive_key("Password123!", salt, "Argon2id", {"memory_cost": 8192, "time_cost": 2, "parallelism": 2})
    assert len(key) == KDF_DERIVED_KEY_LENGTH

def test_invalid_algorithm():
    salt = generate_kdf_salt()
    with pytest.raises(InvalidInputError):
        derive_key("Pass", salt, "UNKNOWN_KDF", {})

def test_out_of_bounds_parameters():
    salt = generate_kdf_salt()
    
    # PBKDF2 below minimum
    with pytest.raises(InvalidInputError):
        derive_key("Pass", salt, "PBKDF2-HMAC-SHA256", {"iterations": 5})
        
    # Argon2id excessive memory (DoS prevention)
    with pytest.raises(InvalidInputError):
        derive_key("Pass", salt, "Argon2id", {"memory_cost": 2**30, "time_cost": 1, "parallelism": 1})
        
    # Scrypt 'n' not a power of 2
    with pytest.raises(InvalidInputError):
        derive_key("Pass", salt, "Scrypt", {"n": 1000, "r": 8, "p": 1})
