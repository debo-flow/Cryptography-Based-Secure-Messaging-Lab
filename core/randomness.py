"""
Secure Randomness System (CSPRNG).
"""
import secrets
from .validation import validate_positive_integer

def generate_random_bytes(length: int) -> bytes:
    validate_positive_integer(length, "Byte length")
    return secrets.token_bytes(length)

def generate_random_token(length: int = 32) -> str:
    validate_positive_integer(length, "Token length")
    return secrets.token_urlsafe(length)

def generate_salt(length: int = 16) -> bytes:
    validate_positive_integer(length, "Salt length")
    return generate_random_bytes(length)
