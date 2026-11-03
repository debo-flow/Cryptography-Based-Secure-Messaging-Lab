"""
Automated Testing for Milestone 24: Message Integrity & Security Analyzer.
Validates structured security reports, Hash engines, and Replay detection wrapping.
"""
import pytest
import json
from core.integrity import (
    calculate_hash, analyze_hmac, analyze_transmission_envelope, analyze_signature_package
)
from core.hmac_engine import generate_hmac_key, calculate_hmac
from core.e2ee import UserIdentity, E2EESession
from core.transmission import send_secure_message
from core.ake import perform_authenticated_key_exchange
from core.ed25519 import generate_ed25519_key_pair
from core.signatures import create_advanced_signature_package

def test_hash_analyzer_support():
    data = b"Testing SHA3!"
    h256 = calculate_hash(data, "SHA-256")
    h3_256 = calculate_hash(data, "SHA3-256")
    
    assert len(h256) > 0
    assert h256 != h3_256 # Distinct families

def test_hmac_analyzer_report():
    key = generate_hmac_key()
    msg = "Data"
    tag = calculate_hmac(key, b"Data", "HMAC-SHA256")
    from core.encoding import bytes_to_b64
    
    # Valid
    report = analyze_hmac(key, msg, bytes_to_b64(tag), "HMAC-SHA256")
    assert report.overall_status == "VALID"
    
    # Tampered
    tampered_tag = bytes_to_b64(b"WRONGTAG!!!")
    report_t = analyze_hmac(key, msg, tampered_tag, "HMAC-SHA256")
    assert report_t.overall_status == "INVALID"
    
    assert "Format Validation" in report.to_csv()

def test_transmission_replay_detection():
    # Setup identities and session
    a_user = UserIdentity("Alice")
    b_user = UserIdentity("Bob")
    s_a, s_b = perform_authenticated_key_exchange(a_user, b_user)
    
    pkg = send_secure_message(s_a, "Test", "AES-256-GCM")
    
    # 1. Valid analysis
    db_mock = []
    report1 = analyze_transmission_envelope(s_b, json.dumps(pkg), db_mock)
    assert report1.overall_status == "VALID"
    
    # 2. Simulate reception (increments rx sequence)
    from core.transmission import receive_secure_message
    receive_secure_message(s_b, json.dumps(pkg))
    
    # 3. Analyze Replay
    report2 = analyze_transmission_envelope(s_b, json.dumps(pkg), db_mock)
    assert report2.overall_status == "INVALID"
    
    replay_check = next(c for c in report2.checks if c["component"] == "Replay Detection")
    assert replay_check["status"] == "FAILED"

def test_signature_trust_analyzer():
    priv, pub = generate_ed25519_key_pair()
    pkg = create_advanced_signature_package(priv, "Data", "Ed25519")
    from core.public_key_manager import get_public_key_fingerprint
    
    fp = get_public_key_fingerprint(pub)
    trusted_db = {"Alice": fp}
    
    # Valid and Trusted
    report = analyze_signature_package(pub, json.dumps(pkg), trusted_db)
    assert report.overall_status == "VALID"
    trust_check = next(c for c in report.checks if c["component"] == "Identity Trust Status")
    assert trust_check["status"] == "VALID"
    
    # Valid but Untrusted
    report_untrusted = analyze_signature_package(pub, json.dumps(pkg), {})
    trust_check_untrusted = next(c for c in report_untrusted.checks if c["component"] == "Identity Trust Status")
    assert trust_check_untrusted["status"] == "UNVERIFIED"
