"""
Advanced RSA Engine.
Implements Key Generation, Serialization, RSA-OAEP Encryption/Decryption, and RSA-PSS Digital Signatures.
"""
import json
import hashlib
from typing import Tuple, Dict, Any
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

from .exceptions import CryptographicOperationError, KeySerializationError, InvalidInputError, AuthenticationError
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes

RSA_SUPPORTED_SIZES = [2048, 3072, 4096]
RSA_PUBLIC_EXPONENT = 65537

SUPPORTED_DIGESTS = {
    "SHA256": hashes.SHA256,
    "SHA384": hashes.SHA384,
    "SHA512": hashes.SHA512
}

def _get_hash_algo(name: str) -> hashes.HashAlgorithm:
    if name not in SUPPORTED_DIGESTS:
        raise InvalidInputError(f"Unsupported digest algorithm: {name}")
    return SUPPORTED_DIGESTS[name]()

def generate_rsa_key_pair(key_size: int = 3072) -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
    if key_size not in RSA_SUPPORTED_SIZES:
        raise InvalidInputError(f"Unsupported RSA key size: {key_size}")
    private_key = rsa.generate_private_key(public_exponent=RSA_PUBLIC_EXPONENT, key_size=key_size)
    return private_key, private_key.public_key()

def serialize_private_key_pem(private_key: rsa.RSAPrivateKey, password: str) -> str:
    try:
        enc_alg = serialization.BestAvailableEncryption(text_to_bytes(password))
        pem = private_key.private_bytes(encoding=serialization.Encoding.PEM, format=serialization.PrivateFormat.PKCS8, encryption_algorithm=enc_alg)
        return bytes_to_text(pem)
    except Exception as e: raise KeySerializationError(f"Failed to serialize private key: {str(e)}")

def serialize_public_key_pem(public_key: rsa.RSAPublicKey) -> str:
    try:
        pem = public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo)
        return bytes_to_text(pem)
    except Exception as e: raise KeySerializationError(f"Failed to serialize public key: {str(e)}")

def load_private_key_pem(pem_data: str, password: str) -> rsa.RSAPrivateKey:
    try:
        key = serialization.load_pem_private_key(text_to_bytes(pem_data), password=text_to_bytes(password))
        if not isinstance(key, rsa.RSAPrivateKey): raise KeySerializationError("Loaded key is not a valid RSA Private Key.")
        return key
    except ValueError: raise KeySerializationError("Incorrect password or malformed private key PEM.")
    except Exception as e: raise KeySerializationError(f"Private key loading failed: {str(e)}")

def load_public_key_pem(pem_data: str) -> rsa.RSAPublicKey:
    try:
        key = serialization.load_pem_public_key(text_to_bytes(pem_data))
        if not isinstance(key, rsa.RSAPublicKey): raise KeySerializationError("Loaded key is not a valid RSA Public Key.")
        return key
    except Exception as e: raise KeySerializationError(f"Public key loading failed or malformed PEM: {str(e)}")

def generate_public_key_fingerprint(public_key: rsa.RSAPublicKey) -> str:
    der = public_key.public_bytes(encoding=serialization.Encoding.DER, format=serialization.PublicFormat.SubjectPublicKeyInfo)
    digest = hashlib.sha256(der).hexdigest()
    return ":".join(digest[i:i+2] for i in range(0, len(digest), 2)).upper()

def get_max_encryption_size(key_size_bits: int, digest_name: str = "SHA256") -> int:
    hLen = _get_hash_algo(digest_name).digest_size
    return (key_size_bits // 8) - (2 * hLen) - 2

# === ENCRYPTION ===
def encrypt_rsa_oaep(public_key: rsa.RSAPublicKey, plaintext: str, digest_name: str = "SHA256", label_str: str = "") -> Dict[str, Any]:
    try:
        key_size = public_key.key_size
        if key_size not in RSA_SUPPORTED_SIZES: raise InvalidInputError(f"Unsupported key size: {key_size}")
        pt_bytes = text_to_bytes(plaintext)
        label_bytes = text_to_bytes(label_str) if label_str else None
        max_size = get_max_encryption_size(key_size, digest_name)
        if len(pt_bytes) > max_size: raise InvalidInputError(f"Plaintext too long.")
        hash_algo = _get_hash_algo(digest_name)
        ciphertext = public_key.encrypt(pt_bytes, padding.OAEP(mgf=padding.MGF1(algorithm=hash_algo), algorithm=hash_algo, label=label_bytes))
        return {
            "version": 2, "algorithm": "RSA-OAEP", "key_size": key_size, "oaep_digest": digest_name, "mgf": "MGF1",
            "mgf_digest": digest_name, "label": bytes_to_b64(label_bytes) if label_bytes else None,
            "encoding": "base64", "ciphertext": bytes_to_b64(ciphertext)
        }
    except InvalidInputError: raise
    except Exception as e: raise CryptographicOperationError(f"RSA Encryption failed: {str(e)}")

def decrypt_rsa_oaep(private_key: rsa.RSAPrivateKey, payload_json: str, provided_label: str = "") -> str:
    try:
        payload = json.loads(payload_json)
        if payload.get("version") != 2: raise InvalidInputError("Unsupported payload version. Expected version 2.")
        algo, ct_b64, key_size_req, oaep_digest, mgf, json_label_b64 = payload.get("algorithm"), payload.get("ciphertext"), payload.get("key_size"), payload.get("oaep_digest"), payload.get("mgf"), payload.get("label")
        if not all([algo, ct_b64, key_size_req, oaep_digest, mgf]): raise InvalidInputError("Malformed RSA payload.")
        if algo != "RSA-OAEP": raise InvalidInputError(f"Unsupported RSA algorithm: {algo}")
        if private_key.key_size != key_size_req: raise InvalidInputError(f"Key size mismatch.")
        ciphertext = b64_to_bytes(ct_b64)
        if len(ciphertext) != private_key.key_size // 8: raise InvalidInputError(f"Ciphertext length mismatch.")
        hash_algo = _get_hash_algo(oaep_digest)
        json_label_bytes = b64_to_bytes(json_label_b64) if json_label_b64 else None
        prov_label_bytes = text_to_bytes(provided_label) if provided_label else None
        if prov_label_bytes and json_label_bytes and prov_label_bytes != json_label_bytes: raise AuthenticationError("Label mismatch.")
        effective_label = prov_label_bytes if prov_label_bytes is not None else json_label_bytes
        plaintext_bytes = private_key.decrypt(ciphertext, padding.OAEP(mgf=padding.MGF1(algorithm=hash_algo), algorithm=hash_algo, label=effective_label))
        return bytes_to_text(plaintext_bytes)
    except ValueError: raise CryptographicOperationError("Decryption failed. Incorrect private key or corrupted ciphertext.")
    except AuthenticationError: raise
    except json.JSONDecodeError: raise InvalidInputError("Payload is not valid JSON.")
    except Exception as e: raise CryptographicOperationError(f"RSA Decryption failed: {str(e)}")

# === DIGITAL SIGNATURES ===
def sign_rsa_pss(private_key: rsa.RSAPrivateKey, message: str, hash_name: str = "SHA256") -> str:
    """Signs a message using RSA-PSS and returns Base64 encoded signature."""
    try:
        hash_algo = _get_hash_algo(hash_name)
        msg_bytes = text_to_bytes(message)
        signature = private_key.sign(
            msg_bytes,
            padding.PSS(
                mgf=padding.MGF1(hash_algo),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hash_algo
        )
        return bytes_to_b64(signature)
    except Exception as e:
        raise CryptographicOperationError(f"RSA-PSS Signing failed: {str(e)}")

def verify_rsa_pss(public_key: rsa.RSAPublicKey, signature_b64: str, message: str, hash_name: str = "SHA256") -> bool:
    """Verifies an RSA-PSS signature. Raises AuthenticationError on failure."""
    try:
        hash_algo = _get_hash_algo(hash_name)
        msg_bytes = text_to_bytes(message)
        sig_bytes = b64_to_bytes(signature_b64)
        public_key.verify(
            sig_bytes,
            msg_bytes,
            padding.PSS(
                mgf=padding.MGF1(hash_algo),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hash_algo
        )
        return True
    except InvalidSignature:
        raise AuthenticationError("Digital Signature Verification Failed: The message was altered or signed by a different key.")
    except Exception as e:
        raise CryptographicOperationError(f"RSA-PSS Verification process failed: {str(e)}")
