"""
Input Validation Utilities.
Safely checks variable bounds without executing cryptographic operations.
"""

from typing import Any
from .exceptions import InvalidInputError

def validate_length(data: bytes | str, min_len: int, max_len: int, field_name: str = "Input") -> None:
    """Validates that a string or byte array falls within acceptable length limits."""
    if not isinstance(data, (bytes, str)):
        raise InvalidInputError(f"{field_name} must be bytes or string.")
    
    length = len(data)
    if length < min_len or length > max_len:
        raise InvalidInputError(
            f"{field_name} length ({length}) is outside allowed bounds ({min_len}-{max_len})."
        )

def validate_positive_integer(value: Any, field_name: str = "Value") -> None:
    """Validates that a value is a positive integer > 0."""
    if not isinstance(value, int) or isinstance(value, bool):
        raise InvalidInputError(f"{field_name} must be an integer.")
    if value <= 0:
        raise InvalidInputError(f"{field_name} must be strictly positive.")
