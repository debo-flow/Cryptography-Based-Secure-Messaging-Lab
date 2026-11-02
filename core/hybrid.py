"""
Advanced Hybrid Encryption Engine.
Combines RSA-OAEP (SHA-256) for Key Encapsulation (KEM) and AES-256-GCM for Data Encapsulation (DEM).
Ensures confidentiality and authenticity of bulk data using a fresh 256-bit Data Encryption Key (DEK).
"""

import json
from typing import Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .randomness import generate_random_bytes
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes
from .rsa import generate_public_key_fingerprint

HYBRID_DEK_SIZE = 32   # 256 bits for AES-256
HYBRID_NONCE_SIZE = 12 # 96 bits for AES-GCM

def generate_hybrid_data_key() -> bytes:
    """Generates a secure 256-bit AES Data Encryption Key (DEK)."""
    return generate_random_bytes(HYBRID_DEK_SIZE)

def generate_hybrid_nonce() -> bytes:
    """Generates a secure 96-bit nonce for AES-GCM."""
    return generate_random_bytes(HYBRID_NONCE_SIZE)

def _build_aad(version: str, scheme: str, fingerprint: str) -> bytes:
    """
    Constructs deterministic Additional Authenticated Data (AAD).
    Cryptographically binds the package metadata to the AES-GCM ciphertext.
    """
    aad_string = f"{version}|{scheme}|{fingerprint}"
    return text_to_bytes(aad_string)

def encrypt_hybrid_message(pub_key: rsa.RSAPublicKey, plaintext: str) -> Dict[str, Any]:
    """
    Executes the Hybrid Encryption workflow:
    1. Gen AES DEK & Nonce.
    2. Encrypt plaintext via AES-GCM.
    3. Wrap DEK via RSA-OAEP.
    4. Bind metadata via AAD.
    """
    try:
        # 1. Generate ephemeral DEK and Nonce
        dek = generate_hybrid_data_key()
        nonce = generate_hybrid_nonce()
        
        # 2. Extract Public Key Fingerprint for metadata binding
        recipient_fp = generate_public_key_fingerprint(pub_key)
        
        # 3. Construct AAD to ensure metadata integrity
        version = "1.0"
        scheme = "RSA-OAEP-SHA256+AES-256-GCM"
        aad_bytes = _build_aad(version, scheme, recipient_fp)
        
        # 4. Encrypt bulk data with AES-256-GCM
        aesgcm = AESGCM(dek)
        pt_bytes = text_to_bytes(plaintext)
        ciphertext_with_tag = aesgcm.encrypt(nonce, pt_bytes, aad_bytes)
        
        # 5. Wrap the DEK with RSA-OAEP (SHA-256 / MGF1-SHA256)
        wrapped_dek = pub_key.encrypt(
            dek,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # 6. Construct Versioned Package
        return {
            "format_version": version,
            "encryption_scheme": scheme,
            "key_wrapping": {
                "algorithm": "RSA-OAEP",
                "hash": "SHA-256",
                "mgf": "MGF1-SHA256",
                "recipient_key_fingerprint": recipient_fp,
                "wrapped_dek": bytes_to_b64(wrapped_dek)
            },
            "content_encryption": {
                "algorithm": "AES-256-GCM",
                "nonce": bytes_to_b64(nonce),
                "ciphertext": bytes_to_b64(ciphertext_with_tag)
            },
            "encoding": "UTF-8"
        }
    except Exception as e:
        raise CryptographicOperationError(f"Hybrid Encryption failed: {str(e)}")

def decrypt_hybrid_message(priv_key: rsa.RSAPrivateKey, payload_json: str) -> str:
    """
    Executes the Hybrid Decryption workflow:
    1. Validate package structure.
    2. Unwrap DEK using RSA private key.
    3. Reconstruct AAD.
    4. Decrypt & Authenticate via AES-GCM.
    """
    try:
        payload = json.loads(payload_json)
        
        # Structure Extraction & Validation
        version = payload.get("format_version")
        scheme = payload.get("encryption_scheme")
        
        if version != "1.0":
            raise InvalidInputError("Unsupported format version.")
        if scheme != "RSA-OAEP-SHA256+AES-256-GCM":
            raise InvalidInputError("Unsupported encryption scheme.")
            
        kw = payload.get("key_wrapping", {})
        ce = payload.get("content_encryption", {})
        
        wrapped_dek_b64 = kw.get("wrapped_dek")
        fingerprint = kw.get("recipient_key_fingerprint")
        nonce_b64 = ce.get("nonce")
        ct_b64 = ce.get("ciphertext")
        
        if not all([wrapped_dek_b64, fingerprint, nonce_b64, ct_b64]):
            raise InvalidInputError("Malformed Hybrid Package: Missing required fields.")
            
        wrapped_dek = b64_to_bytes(wrapped_dek_b64)
        nonce = b64_to_bytes(nonce_b64)
        ciphertext_with_tag = b64_to_bytes(ct_b64)
        
        if len(nonce) != HYBRID_NONCE_SIZE:
            raise InvalidInputError("Invalid AES-GCM nonce length.")
            
        # 1. Unwrap the DEK
        try:
            dek = priv_key.decrypt(
                wrapped_dek,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
        except ValueError:
            raise CryptographicOperationError("DEK Unwrapping failed. Incorrect private key or corrupted wrapped key.")
            
        if len(dek) != HYBRID_DEK_SIZE:
            raise InvalidInputError("Unwrapped DEK has invalid length. Expected 256 bits.")
            
        # 2. Reconstruct AAD
        aad_bytes = _build_aad(version, scheme, fingerprint)
        
        # 3. Authenticate and Decrypt Bulk Payload
        aesgcm = AESGCM(dek)
        try:
            plaintext_bytes = aesgcm.decrypt(nonce, ciphertext_with_tag, aad_bytes)
            return bytes_to_text(plaintext_bytes)
        except InvalidTag:
            raise AuthenticationError("Authentication failed. Ciphertext, Nonce, or Metadata was maliciously modified.")
            
    except json.JSONDecodeError:
        raise InvalidInputError("Payload is not valid JSON.")
    except (AuthenticationError, CryptographicOperationError, InvalidInputError):
        raise
    except Exception as e:
        raise CryptographicOperationError(f"Hybrid Decryption failed: {str(e)}")
