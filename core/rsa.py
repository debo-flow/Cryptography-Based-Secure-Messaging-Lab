"""
Advanced RSA Asymmetric Cryptography Engine.
Implements RSA Key Generation, Serialization, and RSA-OAEP Encryption/Decryption.
Strictly enforces standard secure padding (OAEP/MGF1/SHA-256) and prevents textbook RSA.
"""
import json
import hashlib
from typing import Tuple, Dict
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

from .exceptions import CryptographicOperationError, KeySerializationError, InvalidInputError
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes

RSA_SUPPORTED_SIZES = [2048, 3072, 4096]
RSA_PUBLIC_EXPONENT = 65537

def generate_rsa_key_pair(key_size: int = 3072) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    """Generates a mathematically linked RSA Private and Public key pair."""
    if key_size not in RSA_SUPPORTED_SIZES:
        raise InvalidInputError(f"Unsupported RSA key size: {key_size}. Must be one of {RSA_SUPPORTED_SIZES}.")
    
    private_key = rsa.generate_private_key(
        public_exponent=RSA_PUBLIC_EXPONENT,
        key_size=key_size
    )
    return private_key, private_key.public_key()

def serialize_private_key_pem(private_key: rsa.RSAPrivateKey, password: str) -> str:
    """Serializes a Private Key to PEM format securely protected by a password."""
    try:
        enc_alg = serialization.BestAvailableEncryption(text_to_bytes(password))
        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc_alg
        )
        return bytes_to_text(pem)
    except Exception as e:
        raise KeySerializationError(f"Failed to serialize private key: {str(e)}")

def serialize_public_key_pem(public_key: rsa.RSAPublicKey) -> str:
    """Serializes a Public Key to standard PEM format."""
    try:
        pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return bytes_to_text(pem)
    except Exception as e:
        raise KeySerializationError(f"Failed to serialize public key: {str(e)}")

def load_private_key_pem(pem_data: str, password: str) -> rsa.RSAPrivateKey:
    """Loads and decrypts a Private Key from a PEM string."""
    try:
        key = serialization.load_pem_private_key(
            text_to_bytes(pem_data),
            password=text_to_bytes(password)
        )
        if not isinstance(key, rsa.RSAPrivateKey):
            raise KeySerializationError("Loaded key is not a valid RSA Private Key.")
        return key
    except ValueError as e:
        raise KeySerializationError("Incorrect password or malformed private key PEM.")
    except Exception as e:
        raise KeySerializationError(f"Private key loading failed: {str(e)}")

def load_public_key_pem(pem_data: str) -> rsa.RSAPublicKey:
    """Loads a Public Key from a PEM string."""
    try:
        key = serialization.load_pem_public_key(text_to_bytes(pem_data))
        if not isinstance(key, rsa.RSAPublicKey):
            raise KeySerializationError("Loaded key is not a valid RSA Public Key.")
        return key
    except Exception as e:
        raise KeySerializationError(f"Public key loading failed or malformed PEM: {str(e)}")

def generate_public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    """Generates a SHA-256 fingerprint for public key identity verification."""
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    digest = hashlib.sha256(der).hexdigest()
    # Format as XX:XX:XX...
    return ":".join(digest[i:i+2] for i in range(0, len(digest), 2)).upper()

def get_max_encryption_size(key_size_bits: int) -> int:
    """
    Calculates max plaintext size for RSA-OAEP with SHA-256.
    Formula: (modulus_size_in_bytes) - 2 * (hash_size_in_bytes) - 2
    For SHA-256 (32 bytes): (bits / 8) - 66
    """
    return (key_size_bits // 8) - 2 * 32 - 2

def encrypt_rsa_oaep(public_key: rsa.RSAPublicKey, plaintext: str) -> Dict[str, str]:
    """
    Encrypts data using RSA-OAEP. Output is inherently tied to the recipient's public key.
    Note: RSA does NOT authenticate the sender on its own.
    """
    try:
        key_size = public_key.key_size
        if key_size not in RSA_SUPPORTED_SIZES:
            raise InvalidInputError(f"Unsupported key size: {key_size}")
            
        pt_bytes = text_to_bytes(plaintext)
        max_size = get_max_encryption_size(key_size)
        
        if len(pt_bytes) > max_size:
            raise InvalidInputError(f"Plaintext is too long. Max allowed for RSA-{key_size} OAEP-SHA256 is {max_size} bytes. (Input: {len(pt_bytes)} bytes)")
            
        ciphertext = public_key.encrypt(
            pt_bytes,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        return {
            "version": 1,
            "algorithm": "RSA-OAEP-SHA256",
            "key_size": key_size,
            "ciphertext": bytes_to_b64(ciphertext),
            "encoding": "base64"
        }
    except InvalidInputError:
        raise
    except Exception as e:
        raise CryptographicOperationError(f"RSA Encryption failed: {str(e)}")

def decrypt_rsa_oaep(private_key: rsa.RSAPrivateKey, payload_json: str) -> str:
    """
    Decrypts an RSA-OAEP JSON payload using the corresponding private key.
    """
    try:
        payload = json.loads(payload_json)
        
        algo = payload.get("algorithm")
        ct_b64 = payload.get("ciphertext")
        key_size_req = payload.get("key_size")
        
        if not all([algo, ct_b64, key_size_req]):
            raise InvalidInputError("Malformed RSA payload. Missing required fields.")
            
        if algo != "RSA-OAEP-SHA256":
            raise InvalidInputError(f"Unsupported RSA encryption algorithm: {algo}")
            
        if private_key.key_size != key_size_req:
            raise InvalidInputError(f"Key size mismatch. Payload requires RSA-{key_size_req}, provided key is RSA-{private_key.key_size}.")

        ciphertext = b64_to_bytes(ct_b64)
        
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return bytes_to_text(plaintext_bytes)
        
    except ValueError:
        # Cryptography raises ValueError on decryption failure to prevent padding oracle leaks
        raise CryptographicOperationError("Decryption failed. Incorrect private key or corrupted ciphertext.")
    except json.JSONDecodeError:
        raise InvalidInputError("Payload is not valid JSON.")
    except Exception as e:
        raise CryptographicOperationError(f"RSA Decryption failed: {str(e)}")
