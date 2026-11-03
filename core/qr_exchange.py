"""
Advanced QR-Based Public-Key Exchange Engine (M23).
Provides secure generation, parsing, structural verification, and Ed25519 signing
of out-of-band Identity QR codes.
"""

import json
import time
import io
from typing import Dict, Any, Tuple

import qrcode
import cv2
import numpy as np

from cryptography.hazmat.primitives.asymmetric import ed25519, x25519, rsa, ec
from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes
from .public_key_manager import get_public_key_fingerprint, serialize_public_key, load_public_key
from .ed25519 import sign_message, verify_signature

def _determine_algorithm_string(public_key: Any) -> str:
    """Helper to consistently map key objects to algorithm strings."""
    if isinstance(public_key, ed25519.Ed25519PublicKey): return "Ed25519"
    elif isinstance(public_key, x25519.X25519PublicKey): return "X25519"
    elif isinstance(public_key, rsa.RSAPublicKey): return "RSA"
    elif isinstance(public_key, ec.EllipticCurvePublicKey): return "ECDSA"
    else: raise InvalidInputError("Unsupported public key type for QR exchange.")

def create_qr_payload(identity_id: str, public_key: Any, app_id: str = "CryptoLab-M23") -> Dict[str, Any]:
    """
    Constructs a deterministic, versioned dictionary containing public key metadata.
    Private keys are strictly excluded.
    """
    if not identity_id:
        raise InvalidInputError("Identity ID cannot be empty.")
        
    algorithm = _determine_algorithm_string(public_key)
    
    return {
        "format_version": "1.0",
        "app_id": app_id,
        "identity_id": identity_id,
        "algorithm": algorithm,
        "public_key_format": "PEM",
        "public_key_data": serialize_public_key(public_key, "PEM"),
        "fingerprint": get_public_key_fingerprint(public_key),
        "timestamp": time.time()
    }

def sign_qr_payload(payload: Dict[str, Any], private_key: ed25519.Ed25519PrivateKey) -> Dict[str, Any]:
    """
    Self-signs the canonical JSON payload using the identity's Ed25519 private key.
    Provides proof of possession.
    """
    if not isinstance(private_key, ed25519.Ed25519PrivateKey):
        raise InvalidInputError("Only Ed25519 private keys are supported for QR self-signatures.")
        
    # Remove existing signature to ensure canonical determinism
    payload_copy = payload.copy()
    if "signature" in payload_copy:
        del payload_copy["signature"]
        
    canonical_data = json.dumps(payload_copy, sort_keys=True, separators=(',', ':'))
    payload_copy["signature"] = sign_message(private_key, canonical_data)
    
    return payload_copy

def generate_qr_image(payload: Dict[str, Any], error_correction: int = qrcode.constants.ERROR_CORRECT_H) -> bytes:
    """
    Serializes the JSON payload and generates a high-error-correction PNG QR Code.
    """
    try:
        json_data = json.dumps(payload, sort_keys=True, separators=(',', ':'))
        
        qr = qrcode.QRCode(
            version=None,
            error_correction=error_correction,
            box_size=10,
            border=4,
        )
        qr.add_data(json_data)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except Exception as e:
        raise CryptographicOperationError(f"QR Code generation failed: {str(e)}")

def decode_qr_image(image_bytes: bytes) -> str:
    """
    Decodes a QR code from raw image bytes using OpenCV.
    """
    try:
        np_arr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(np_arr, cv2.IMREAD_COLOR)
        
        if img is None:
            raise InvalidInputError("Uploaded file is not a valid or readable image.")
            
        detector = cv2.QRCodeDetector()
        data, bbox, _ = detector.detectAndDecode(img)
        
        if not data:
            raise InvalidInputError("No QR code detected or payload could not be decoded.")
            
        return data
    except InvalidInputError:
        raise
    except Exception as e:
        raise CryptographicOperationError(f"QR Code decoding failed: {str(e)}")

def verify_qr_payload(payload_json: str) -> Tuple[Dict[str, Any], Any]:
    """
    Strictly validates the QR payload structure, recalculates the public key fingerprint,
    and verifies the Ed25519 signature (if present and applicable).
    Returns the validated payload dictionary and the reconstructed cryptographic Public Key object.
    """
    try:
        payload = json.loads(payload_json)
        
        # 1. Structural Validation
        version = payload.get("format_version")
        if version != "1.0":
            raise InvalidInputError(f"Unsupported QR payload version: {version}")
            
        identity_id = payload.get("identity_id")
        algo = payload.get("algorithm")
        pk_format = payload.get("public_key_format")
        pk_data = payload.get("public_key_data")
        claimed_fingerprint = payload.get("fingerprint")
        
        if not all([identity_id, algo, pk_format, pk_data, claimed_fingerprint]):
            raise InvalidInputError("Malformed QR Payload. Missing required metadata fields.")
            
        if pk_format != "PEM":
            raise InvalidInputError(f"Unsupported public key format: {pk_format}")
            
        # 2. Key Reconstruction & Algorithm Verification
        public_key = load_public_key(pk_data)
        actual_algo = _determine_algorithm_string(public_key)
        
        if algo != actual_algo:
            raise AuthenticationError(f"Algorithm mismatch: Payload claims {algo}, but key is {actual_algo}.")
            
        # 3. Fingerprint Verification (The core of Out-Of-Band Trust)
        actual_fingerprint = get_public_key_fingerprint(public_key)
        if actual_fingerprint != claimed_fingerprint:
            raise AuthenticationError(f"CRITICAL FINGERPRINT MISMATCH! Claimed: {claimed_fingerprint}, Actual: {actual_fingerprint}. The key was tampered with.")
            
        # 4. Signature Verification (If Present)
        signature = payload.get("signature")
        if signature:
            # Reconstruct the canonical data identically to signing
            payload_copy = payload.copy()
            del payload_copy["signature"]
            canonical_data = json.dumps(payload_copy, sort_keys=True, separators=(',', ':'))
            
            # If the public key in the payload is Ed25519, we use it to verify self-signatures
            if algo == "Ed25519":
                try:
                    verify_signature(public_key, signature, canonical_data)
                except AuthenticationError:
                    raise AuthenticationError("Invalid QR Signature. The payload was tampered with after signing.")
            else:
                # In this lab, we only enforce self-signatures for Ed25519 identity keys.
                pass 
                
        return payload, public_key
        
    except json.JSONDecodeError:
        raise InvalidInputError("Payload is not valid JSON.")
    except (InvalidInputError, AuthenticationError):
        raise
    except Exception as e:
        raise CryptographicOperationError(f"QR payload verification failed: {str(e)}")
