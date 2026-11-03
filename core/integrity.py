"""
Advanced Message Integrity & Security Analysis Engine (M24).
Provides structural, cryptographic, and replay analysis for Hashes, HMACs, AEAD Envelopes, and Signatures.
"""

import json
import time
import uuid
import io
import csv
from typing import Dict, Any, List, Optional, Tuple
from cryptography.hazmat.primitives import hashes

from .exceptions import CryptographicOperationError, InvalidInputError, AuthenticationError
from .encoding import text_to_bytes, bytes_to_text, bytes_to_b64, b64_to_bytes
from .hmac_engine import verify_hmac
from .signatures import validate_advanced_signature_package
from .transmission import receive_secure_message
from .e2ee import E2EESession

SUPPORTED_HASHES = {
    "SHA-256": hashes.SHA256,
    "SHA-384": hashes.SHA384,
    "SHA-512": hashes.SHA512,
    "SHA3-256": hashes.SHA3_256,
    "SHA3-384": hashes.SHA3_384,
    "SHA3-512": hashes.SHA3_512
}

class SecurityReport:
    """Standardized report for integrity validation results."""
    def __init__(self, target_id: str, target_type: str):
        self.report_id = str(uuid.uuid4())
        self.timestamp = time.time()
        self.target_id = target_id
        self.target_type = target_type
        self.checks: List[Dict[str, str]] = []
        self.overall_status = "VALID"
        
    def add_check(self, component: str, status: str, details: str):
        self.checks.append({"component": component, "status": status, "details": details})
        if status in ["INVALID", "FAILED"]:
            self.overall_status = "INVALID"
            
    def to_dict(self) -> Dict[str, Any]:
        return {
            "report_id": self.report_id,
            "timestamp": self.timestamp,
            "target_id": self.target_id,
            "target_type": self.target_type,
            "overall_status": self.overall_status,
            "checks": self.checks
        }
        
    def to_csv(self) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Component", "Status", "Details"])
        for c in self.checks:
            writer.writerow([c["component"], c["status"], c["details"]])
        return output.getvalue()

def calculate_hash(data: bytes, algorithm: str) -> str:
    """Calculates a cryptographic hash for data."""
    if algorithm not in SUPPORTED_HASHES:
        raise InvalidInputError(f"Unsupported Hash: {algorithm}")
    digest = hashes.Hash(SUPPORTED_HASHES[algorithm]())
    digest.update(data)
    return bytes_to_b64(digest.finalize())

def calculate_file_hash_stream(file_stream: io.BytesIO, algorithm: str) -> str:
    """Calculates a streaming cryptographic hash for large files."""
    if algorithm not in SUPPORTED_HASHES:
        raise InvalidInputError(f"Unsupported Hash: {algorithm}")
    digest = hashes.Hash(SUPPORTED_HASHES[algorithm]())
    for chunk in iter(lambda: file_stream.read(4096), b""):
        digest.update(chunk)
    return bytes_to_b64(digest.finalize())

def analyze_hmac(key: bytes, message: str, provided_tag_b64: str, algorithm: str) -> SecurityReport:
    """Analyzes an HMAC authentication attempt."""
    report = SecurityReport("HMAC-Analysis", "Authentication")
    try:
        tag_bytes = b64_to_bytes(provided_tag_b64)
        report.add_check("Format Validation", "VALID", "Base64 tag parsed successfully.")
    except Exception:
        report.add_check("Format Validation", "INVALID", "Malformed Base64 tag.")
        return report
        
    try:
        verify_hmac(key, text_to_bytes(message), tag_bytes, algorithm)
        report.add_check("HMAC Verification", "VALID", "Constant-time tag verification passed.")
    except AuthenticationError as e:
        report.add_check("HMAC Verification", "FAILED", str(e))
    except Exception as e:
        report.add_check("HMAC Verification", "INVALID", f"Algorithm error: {str(e)}")
        
    return report

def analyze_signature_package(public_key: Any, payload_json: str, trusted_fingerprints: Dict[str, str] = None) -> SecurityReport:
    """Analyzes a Digital Signature package, including metadata structure and trust verification."""
    report = SecurityReport("Signature-Analysis", "Digital Signature")
    
    # Structural Check
    try:
        payload = json.loads(payload_json)
        pkg_fp = payload.get("public_key_fingerprint")
        algo = payload.get("algorithm")
        report.add_check("Format Validation", "VALID", f"Valid JSON. Algorithm: {algo}")
    except Exception as e:
        report.add_check("Format Validation", "INVALID", f"Malformed payload: {str(e)}")
        return report

    # Cryptographic Verification
    try:
        validate_advanced_signature_package(public_key, payload_json)
        report.add_check("Signature Verification", "VALID", "Mathematical signature is cryptographically valid.")
    except AuthenticationError as e:
        report.add_check("Signature Verification", "FAILED", f"Signature or Key Mismatch: {str(e)}")
    except InvalidInputError as e:
        report.add_check("Signature Verification", "INVALID", f"Structural Error: {str(e)}")
        
    # Trust Verification (OOB)
    if trusted_fingerprints is not None and pkg_fp:
        if pkg_fp in trusted_fingerprints.values():
            report.add_check("Identity Trust Status", "VALID", "Signer public key fingerprint matches explicitly trusted database.")
        else:
            report.add_check("Identity Trust Status", "UNVERIFIED", "Signature is mathematically valid, but identity is NOT trusted out-of-band.")

    return report

def analyze_transmission_envelope(session: E2EESession, payload_json: str, db_history: List[Dict[str, Any]]) -> SecurityReport:
    """
    Analyzes an E2EE M20 Transmission Envelope for Replay Attacks, Metadata consistency, and AEAD tampering.
    """
    try:
        payload = json.loads(payload_json)
        msg_id = payload.get("message_id", "UNKNOWN")
    except Exception:
        msg_id = "UNKNOWN"
        
    report = SecurityReport(msg_id, "E2EE Transmission Envelope")

    # 1. Format & Metadata Analysis
    try:
        payload = json.loads(payload_json)
        req_fields = ["protocol_version", "message_id", "session_id", "sender_id", "recipient_id", "sequence_number", "cipher", "ciphertext"]
        missing = [f for f in req_fields if f not in payload]
        if missing:
            report.add_check("Metadata Consistency", "INVALID", f"Missing fields: {', '.join(missing)}")
        else:
            report.add_check("Metadata Consistency", "VALID", "All mandatory envelope fields present.")
            
        seq_num = payload.get("sequence_number")
        if not isinstance(seq_num, int):
            report.add_check("Format Validation", "INVALID", "Sequence number is not an integer.")
    except Exception as e:
        report.add_check("Format Validation", "INVALID", f"Malformed JSON: {str(e)}")
        return report

    # 2. Replay Detection (using DB history & Session State)
    if isinstance(seq_num, int):
        if seq_num <= session.rx_sequence:
            report.add_check("Replay Detection", "FAILED", f"Sequence {seq_num} is <= current Rx state {session.rx_sequence}. Replay blocked.")
        else:
            report.add_check("Replay Detection", "VALID", "Sequence monotonicity is strictly preserved.")
            
        # Check if Message ID already exists in DB
        if any(msg["message_id"] == payload["message_id"] for msg in db_history):
            report.add_check("Duplicate Detection", "FAILED", f"Message ID {payload['message_id']} has already been processed.")
        else:
            report.add_check("Duplicate Detection", "VALID", "Message ID is unique in this session.")

    # 3. AEAD Authentication Verification
    try:
        # We rely on the existing rigorous engine. It throws explicit exceptions on failure.
        # We do NOT commit the sequence state here, this is just analysis.
        temp_rx = session.rx_sequence
        receive_secure_message(session, payload_json)
        session.rx_sequence = temp_rx # Revert state since this is purely a dry-run analysis
        
        report.add_check("AEAD Authentication", "VALID", "Ciphertext, Nonce, and AAD perfectly verify.")
    except AuthenticationError as e:
        report.add_check("AEAD Authentication", "FAILED", f"Tampering detected: {str(e)}")
    except InvalidInputError as e:
        report.add_check("AEAD Authentication", "INVALID", f"Routing or Metadata structural error: {str(e)}")
        
    return report
