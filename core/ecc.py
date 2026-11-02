"""
Elliptic Curve Cryptography (ECC) Engine.
Handles SECP256R1, SECP384R1, and SECP521R1 key generation and ECDSA signing.
Signatures are output in standard ASN.1 DER format (Base64 encoded).
"""

from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from .exceptions import InvalidInputError, CryptographicOperationError, AuthenticationError
from .encoding import text_to_bytes, b64_to_bytes, bytes_to_b64

SUPPORTED_CURVES = {
    "SECP256R1": ec.SECP256R1(),
    "SECP384R1": ec.SECP384R1(),
    "SECP521R1": ec.SECP521R1()
}

SUPPORTED_DIGESTS = {
    "SHA256": hashes.SHA256,
    "SHA384": hashes.SHA384,
    "SHA512": hashes.SHA512
}

def generate_ecc_key_pair(curve_name: str = "SECP256R1") -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generates an Elliptic Curve private/public key pair based on the specified curve."""
    if curve_name not in SUPPORTED_CURVES:
        raise InvalidInputError(f"Unsupported ECC Curve: {curve_name}")
    
    private_key = ec.generate_private_key(SUPPORTED_CURVES[curve_name])
    public_key = private_key.public_key()
    return private_key, public_key

def sign_ecdsa(private_key: ec.EllipticCurvePrivateKey, message: str, hash_name: str = "SHA256") -> str:
    """
    Signs a message using ECDSA and returns a Base64 encoded signature.
    The cryptography library natively encodes ECDSA signatures in standard ASN.1 DER format.
    """
    if hash_name not in SUPPORTED_DIGESTS:
        raise InvalidInputError(f"Unsupported digest: {hash_name}")
        
    try:
        hash_algo = SUPPORTED_DIGESTS[hash_name]()
        msg_bytes = text_to_bytes(message)
        signature = private_key.sign(msg_bytes, ec.ECDSA(hash_algo))
        return bytes_to_b64(signature)
    except Exception as e:
        raise CryptographicOperationError(f"ECDSA Signing failed: {str(e)}")

def verify_ecdsa(public_key: ec.EllipticCurvePublicKey, signature_b64: str, message: str, hash_name: str = "SHA256") -> bool:
    """
    Verifies an ECDSA signature using the corresponding public key and hash algorithm.
    Raises AuthenticationError on failure.
    """
    if hash_name not in SUPPORTED_DIGESTS:
        raise InvalidInputError(f"Unsupported digest: {hash_name}")
        
    try:
        hash_algo = SUPPORTED_DIGESTS[hash_name]()
        msg_bytes = text_to_bytes(message)
        sig_bytes = b64_to_bytes(signature_b64)
        
        public_key.verify(sig_bytes, msg_bytes, ec.ECDSA(hash_algo))
        return True
    except InvalidSignature:
        raise AuthenticationError("Digital Signature Verification Failed: The message was altered or signed by a different key.")
    except Exception as e:
        raise CryptographicOperationError(f"ECDSA Verification process failed: {str(e)}")
