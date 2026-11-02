"""
Elliptic Curve Cryptography (ECC) Engine.
Handles SECP256R1, SECP384R1, and SECP521R1 key generation.
Note: Raw ECC keys here are educational. In practice, they are used for ECDH or ECDSA.
"""
from cryptography.hazmat.primitives.asymmetric import ec
from typing import Tuple
from .exceptions import InvalidInputError

SUPPORTED_CURVES = {
    "SECP256R1": ec.SECP256R1(),
    "SECP384R1": ec.SECP384R1(),
    "SECP521R1": ec.SECP521R1()
}

def generate_ecc_key_pair(curve_name: str = "SECP256R1") -> Tuple[ec.EllipticCurvePrivateKey, ec.EllipticCurvePublicKey]:
    """Generates an Elliptic Curve private/public key pair based on the specified curve."""
    if curve_name not in SUPPORTED_CURVES:
        raise InvalidInputError(f"Unsupported ECC Curve: {curve_name}")
    
    private_key = ec.generate_private_key(SUPPORTED_CURVES[curve_name])
    public_key = private_key.public_key()
    return private_key, public_key
