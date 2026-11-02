"""
Centralized Error Handling Framework for Cryptographic Operations.
Ensures safe exception throwing without leaking sensitive application states.
"""

class CryptographicError(Exception):
    """Base exception for all cryptographic operations in the laboratory."""
    pass

class InvalidInputError(CryptographicError):
    """Raised when cryptographic input fails validation (length, type)."""
    pass

class InvalidKeyMetadataError(CryptographicError):
    """Raised when key metadata is malformed or invalid."""
    pass

class InvalidNonceError(CryptographicError):
    """Raised when a nonce violates uniqueness or length requirements."""
    pass

class InvalidSaltError(CryptographicError):
    """Raised when a salt is structurally invalid."""
    pass

class EncodingError(CryptographicError):
    """Raised when string/bytes conversion fails."""
    pass

class AlgorithmNotAvailableError(CryptographicError):
    """Raised when an algorithm is requested but not yet implemented/registered."""
    pass

class CryptographicOperationError(CryptographicError):
    """Raised when a cryptographic primitive fails internally."""
    pass

class AuthenticationError(CryptographicError):
    """Raised when MAC/Signature validation fails. Indicates tampering or wrong key."""
    pass
