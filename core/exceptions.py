"""
Centralized Error Handling Framework for Cryptographic Operations.
"""

class CryptographicError(Exception): pass
class InvalidInputError(CryptographicError): pass
class InvalidKeyMetadataError(CryptographicError): pass
class InvalidNonceError(CryptographicError): pass
class InvalidSaltError(CryptographicError): pass
class EncodingError(CryptographicError): pass
class AlgorithmNotAvailableError(CryptographicError): pass
class CryptographicOperationError(CryptographicError): pass

class AuthenticationError(CryptographicError):
    """Raised when MAC/Signature validation fails. Indicates tampering or wrong key."""
    pass
