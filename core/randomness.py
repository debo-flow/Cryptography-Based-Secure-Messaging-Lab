"""
Secure Randomness System.
Relies exclusively on cryptographically secure pseudorandom number generators (CSPRNG).
No usage of the standard 'random' module is permitted.
"""

import secrets
from .validation import validate_positive_integer

def generate_random_bytes(length: int) -> bytes:
    """
    Generates cryptographically secure random bytes.
    Used for symmetric keys and raw nonce generation.
    """
    validate_positive_integer(length, "Byte length")
    return secrets.token_bytes(length)

def generate_random_token(length: int = 32) -> str:
    """
    Generates a cryptographically secure, URL-safe text token.
    Ideal for session identifiers and metadata IDs.
    """
    validate_positive_integer(length, "Token length")
    return secrets.token_urlsafe(length)

def generate_salt(length: int = 16) -> bytes:
    """
    Generates a secure salt for password-based derivation algorithms.
    """
    validate_positive_integer(length, "Salt length")
    return generate_random_bytes(length)
