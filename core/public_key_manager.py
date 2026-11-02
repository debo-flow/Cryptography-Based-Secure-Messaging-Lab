"""
Centralized Public-Key Serialization and Inspection Engine.
Handles PEM/DER encoding and decoding for all supported asymmetric algorithms (RSA, ECC, X25519, Ed25519).
"""
import hashlib
from typing import Any, Dict
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, x25519, ed25519
from .exceptions import KeySerializationError, InvalidInputError
from .encoding import text_to_bytes, bytes_to_text

def serialize_public_key(public_key: Any, fmt: str = "PEM") -> str | bytes:
    """Serializes a public key to PEM (str) or DER (bytes)."""
    try:
        encoding = serialization.Encoding.PEM if fmt.upper() == "PEM" else serialization.Encoding.DER
        out_bytes = public_key.public_bytes(
            encoding=encoding,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return bytes_to_text(out_bytes) if fmt.upper() == "PEM" else out_bytes
    except Exception as e:
        raise KeySerializationError(f"Failed to serialize public key: {str(e)}")

def serialize_private_key(private_key: Any, password: str, fmt: str = "PEM") -> str | bytes:
    """Serializes a private key with strong password encryption."""
    if not password:
        raise InvalidInputError("A password is strictly required to export a private key.")
    try:
        encoding = serialization.Encoding.PEM if fmt.upper() == "PEM" else serialization.Encoding.DER
        enc_alg = serialization.BestAvailableEncryption(text_to_bytes(password))
        out_bytes = private_key.private_bytes(
            encoding=encoding,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_alg
        )
        return bytes_to_text(out_bytes) if fmt.upper() == "PEM" else out_bytes
    except Exception as e:
        raise KeySerializationError(f"Failed to serialize private key: {str(e)}")

def load_public_key(data: str | bytes) -> Any:
    """Auto-detects and loads a PEM or DER public key."""
    raw_data = text_to_bytes(data) if isinstance(data, str) else data
    try:
        if b"-----BEGIN" in raw_data:
            return serialization.load_pem_public_key(raw_data)
        else:
            return serialization.load_der_public_key(raw_data)
    except Exception as e:
        raise KeySerializationError(f"Failed to load public key. Ensure it is a valid PEM/DER format: {str(e)}")

def load_private_key(data: str | bytes, password: str) -> Any:
    """Auto-detects and loads a PEM or DER encrypted private key."""
    raw_data = text_to_bytes(data) if isinstance(data, str) else data
    pass_bytes = text_to_bytes(password) if password else None
    try:
        if b"-----BEGIN" in raw_data:
            return serialization.load_pem_private_key(raw_data, password=pass_bytes)
        else:
            return serialization.load_der_private_key(raw_data, password=pass_bytes)
    except ValueError:
        raise KeySerializationError("Incorrect password or badly formed private key.")
    except Exception as e:
        raise KeySerializationError(f"Failed to load private key: {str(e)}")

def get_public_key_fingerprint(public_key: Any) -> str:
    """Generates a SHA-256 fingerprint over the standard SubjectPublicKeyInfo DER representation."""
    try:
        der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
        digest = hashlib.sha256(der).hexdigest()
        return ":".join(digest[i:i+2] for i in range(0, len(digest), 2)).upper()
    except Exception as e:
        raise CryptographicOperationError(f"Failed to generate fingerprint: {str(e)}")

def validate_public_key(public_key: Any) -> bool:
    """Validates that the object is a recognized public key primitive."""
    valid_types = (rsa.RSAPublicKey, ec.EllipticCurvePublicKey, x25519.X25519PublicKey, ed25519.Ed25519PublicKey)
    if not isinstance(public_key, valid_types):
        raise InvalidInputError("The provided object is not a supported public key type.")
    return True

def validate_private_key(private_key: Any) -> bool:
    """Validates that the object is a recognized private key primitive."""
    valid_types = (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey, ed25519.Ed25519PrivateKey)
    if not isinstance(private_key, valid_types):
        raise InvalidInputError("The provided object is not a supported private key type.")
    return True

def inspect_key(key: Any) -> Dict[str, Any]:
    """Extracts metadata from a public or private key for educational inspection."""
    is_private = isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey, x25519.X25519PrivateKey, ed25519.Ed25519PrivateKey))
    
    # Safely extract public key for fingerprinting without exposing private data
    pub_key = key.public_key() if is_private else key
    
    info = {
        "key_classification": "Private Key (SECRET)" if is_private else "Public Key (SHAREABLE)",
        "public_fingerprint": get_public_key_fingerprint(pub_key)
    }
    
    if isinstance(pub_key, rsa.RSAPublicKey):
        info["algorithm"] = "RSA"
        info["capabilities"] = "Encryption (OAEP), Signatures (PSS/PKCS1v15)"
        info["key_size_bits"] = pub_key.key_size
        info["public_exponent"] = pub_key.public_numbers().e
    elif isinstance(pub_key, ec.EllipticCurvePublicKey):
        info["algorithm"] = "Elliptic Curve Cryptography (ECC)"
        info["capabilities"] = "Key Exchange (ECDH), Signatures (ECDSA)"
        info["curve"] = pub_key.curve.name
        info["key_size_bits"] = pub_key.curve.key_size
    elif isinstance(pub_key, x25519.X25519PublicKey):
        info["algorithm"] = "X25519"
        info["capabilities"] = "Key Agreement / Exchange ONLY"
        info["key_size_bits"] = 256
    elif isinstance(pub_key, ed25519.Ed25519PublicKey):
        info["algorithm"] = "Ed25519"
        info["capabilities"] = "Digital Signatures ONLY"
        info["key_size_bits"] = 256
    else:
        info["algorithm"] = "Unknown"
        
    return info
