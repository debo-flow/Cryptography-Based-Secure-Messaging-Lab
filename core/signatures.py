"""
Advanced Digital Signature Engine.
Unifies RSA-PSS, ECDSA, and Ed25519 signing and verification into a structured, versioned format.
Strictly separates Authenticity/Integrity (Signatures) from Confidentiality (Encryption).
"""

import json
from datetime import datetime, timezone
from typing import Dict, Any

from cryptography.hazmat.primitives.asymmetric import rsa, ec, ed25519

from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes
from .public_key_manager import get_public_key_fingerprint, serialize_public_key, load_public_key
from .rsa import sign_rsa_pss, verify_rsa_pss
from .ecc import sign_ecdsa, verify_ecdsa
from .ed25519 import sign_message as sign_ed25519, verify_signature as verify_ed25519


def create_signature_package(private_key: Any, message: str, algorithm_config: str) -> Dict[str, Any]:
    """
    Signs a message using the provided private key and configuration.
    Generates a standardized JSON metadata package containing the signature.
    """
    if not message:
        raise InvalidInputError("Message cannot be empty for signing.")
        
    try:
        # Generate Signature based on Key Type and Config
        if isinstance(private_key, rsa.RSAPrivateKey):
            if not algorithm_config.startswith("RSA-PSS-"):
                raise InvalidInputError(f"Invalid algorithm config for RSA key: {algorithm_config}")
            hash_name = algorithm_config.split("RSA-PSS-")[1]
            sig_b64 = sign_rsa_pss(private_key, message, hash_name)
            pub_key = private_key.public_key()
            
        elif isinstance(private_key, ec.EllipticCurvePrivateKey):
            if not algorithm_config.startswith("ECDSA-"):
                raise InvalidInputError(f"Invalid algorithm config for ECC key: {algorithm_config}")
            hash_name = algorithm_config.split("-")[-1]
            sig_b64 = sign_ecdsa(private_key, message, hash_name)
            pub_key = private_key.public_key()
            
        elif isinstance(private_key, ed25519.Ed25519PrivateKey):
            if algorithm_config != "Ed25519":
                raise InvalidInputError(f"Invalid algorithm config for Ed25519 key: {algorithm_config}")
            sig_b64 = sign_ed25519(private_key, message)
            pub_key = private_key.public_key()
            
        else:
            raise InvalidInputError("Unsupported private key type for digital signatures.")

        # Construct Standardized Output Package
        return {
            "format_version": "1.0",
            "signature_type": "Digital Signature",
            "algorithm": algorithm_config,
            "message_encoding": "UTF-8",
            "message": bytes_to_b64(text_to_bytes(message)),
            "signature": sig_b64,
            "public_key": serialize_public_key(pub_key, fmt="PEM"),
            "public_key_fingerprint": get_public_key_fingerprint(pub_key),
            "created_at": datetime.now(timezone.utc).isoformat()
        }
        
    except InvalidInputError:
        raise
    except Exception as e:
        raise CryptographicOperationError(f"Digital signing failed: {str(e)}")


def validate_signature_package(public_key: Any, payload_json: str) -> str:
    """
    Parses a JSON signature package, enforces structure constraints,
    verifies the signature against the provided public key, and returns the verified message.
    """
    try:
        payload = json.loads(payload_json)
        
        # 1. Structural Validation
        version = payload.get("format_version")
        if version != "1.0":
            raise InvalidInputError(f"Unsupported signature format version: {version}")
            
        if payload.get("signature_type") != "Digital Signature":
            raise InvalidInputError("Payload is not a Digital Signature package.")
            
        algorithm_config = payload.get("algorithm")
        msg_b64 = payload.get("message")
        sig_b64 = payload.get("signature")
        pkg_fingerprint = payload.get("public_key_fingerprint")
        
        if not all([algorithm_config, msg_b64, sig_b64, pkg_fingerprint]):
            raise InvalidInputError("Malformed signature package. Missing required fields.")
            
        message = bytes_to_text(b64_to_bytes(msg_b64))
        
        # 2. Key Validation & Fingerprint Matching
        # We ensure the key provided by the verifier actually matches the key the package claims signed it.
        actual_fingerprint = get_public_key_fingerprint(public_key)
        if actual_fingerprint != pkg_fingerprint:
            raise AuthenticationError(f"Key mismatch. Provided public key ({actual_fingerprint}) does not match package fingerprint ({pkg_fingerprint}).")
            
        # 3. Signature Verification
        if isinstance(public_key, rsa.RSAPublicKey):
            if not algorithm_config.startswith("RSA-PSS-"):
                raise InvalidInputError(f"Mismatch: Package claims {algorithm_config}, but provided an RSA key.")
            hash_name = algorithm_config.split("RSA-PSS-")[1]
            verify_rsa_pss(public_key, sig_b64, message, hash_name)
            
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            if not algorithm_config.startswith("ECDSA-"):
                raise InvalidInputError(f"Mismatch: Package claims {algorithm_config}, but provided an ECC key.")
            hash_name = algorithm_config.split("-")[-1]
            verify_ecdsa(public_key, sig_b64, message, hash_name)
            
        elif isinstance(public_key, ed25519.Ed25519PublicKey):
            if algorithm_config != "Ed25519":
                raise InvalidInputError(f"Mismatch: Package claims {algorithm_config}, but provided an Ed25519 key.")
            verify_ed25519(public_key, sig_b64, message)
            
        else:
            raise InvalidInputError("Unsupported public key type for verification.")

        # Verification succeeded (AuthenticationError would be raised otherwise)
        return message

    except json.JSONDecodeError:
        raise InvalidInputError("Payload is not valid JSON.")
    except (InvalidInputError, AuthenticationError):
        raise
    except Exception as e:
        raise CryptographicOperationError(f"Verification process failed: {str(e)}")
