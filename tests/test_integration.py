"""
End-to-End Workflow Integration Tests (M28).
Tests the entire pipeline from Identity Gen -> AKE -> Transmission -> Analyzer without network reliance.
"""
import pytest
import json
from core.e2ee import UserIdentity
from core.ake import perform_authenticated_key_exchange
from core.transmission import send_secure_message, receive_secure_message
from core.integrity import analyze_transmission_envelope

def test_full_messaging_lifecycle():
    # 1. Gen Identities
    alice = UserIdentity("Alice")
    bob = UserIdentity("Bob")
    
    # 2. Authenticated Key Exchange (M19)
    s_alice, s_bob = perform_authenticated_key_exchange(alice, bob)
    
    # 3. Encrypt & Transmit (M20)
    msg = "Full Lifecycle Integration Test"
    pkg = send_secure_message(s_alice, msg, "ChaCha20-Poly1305")
    
    # 4. Integrity Analysis (M24)
    report = analyze_transmission_envelope(s_bob, json.dumps(pkg), [])
    assert report.overall_status == "VALID"
    
    # 5. Receive & Decrypt
    recovered = receive_secure_message(s_bob, json.dumps(pkg))
    assert recovered == msg
