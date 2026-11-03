"""
Automated Testing for Milestone 18: End-to-End Messaging Foundation.
Validates session routing, metadata binding, and multi-algorithm encryption.
"""
import pytest
import json
from core.e2ee import (
    UserIdentity, simulate_session_establishment, encrypt_e2ee_message, decrypt_e2ee_message, E2EE_SUPPORTED_CIPHERS
)
from core.exceptions import InvalidInputError, AuthenticationError

@pytest.fixture(scope="module")
def users():
    return UserIdentity("Alice"), UserIdentity("Bob")

@pytest.fixture(scope="module")
def sessions(users):
    alice, bob = users
    return simulate_session_establishment(alice, bob)

@pytest.mark.parametrize("algorithm", E2EE_SUPPORTED_CIPHERS)
def test_e2ee_round_trip(sessions, algorithm):
    s_alice, s_bob = sessions
    message = f"E2EE Routing Test via {algorithm}"
    
    # Alice sends to Bob
    pkg = encrypt_e2ee_message(s_alice, message, algorithm)
    assert pkg["sender_id"] == "Alice"
    assert pkg["recipient_id"] == "Bob"
    
    # Bob decrypts
    recovered = decrypt_e2ee_message(s_bob, json.dumps(pkg))
    assert recovered == message

def test_wrong_recipient_rejection(users, sessions):
    s_alice, _ = sessions
    eve = UserIdentity("Eve")
    _, s_eve = simulate_session_establishment(users[0], eve) # Alice and Eve session
    
    # Alice sends a message to Bob in their session
    pkg = encrypt_e2ee_message(s_alice, "For Bob's eyes only", "AES-256-GCM")
    
    # Eve intercepts and tries to decrypt it with her session key with Alice
    with pytest.raises(InvalidInputError) as exc:
        decrypt_e2ee_message(s_eve, json.dumps(pkg))
    assert "Message belongs to a different session" in str(exc.value)

def test_tampered_routing_metadata(sessions):
    s_alice, s_bob = sessions
    pkg = encrypt_e2ee_message(s_alice, "Sensitive Payload", "ChaCha20-Poly1305")
    
    # Attack: Man in the middle alters the sender ID
    pkg["sender_id"] = "Eve"
    
    with pytest.raises(InvalidInputError) as exc:
        decrypt_e2ee_message(s_bob, json.dumps(pkg))
    assert "Message sender does not match" in str(exc.value)

def test_tampered_ciphertext(sessions):
    s_alice, s_bob = sessions
    pkg = encrypt_e2ee_message(s_alice, "Bank transfer $100", "AES-256-GCM")
    
    from core.encoding import b64_to_bytes, bytes_to_b64
    ct = b64_to_bytes(pkg["ciphertext"])
    tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
    pkg["ciphertext"] = bytes_to_b64(tampered)
    
    with pytest.raises(AuthenticationError):
        decrypt_e2ee_message(s_bob, json.dumps(pkg))

def test_terminated_session(users):
    s_a, s_b = simulate_session_establishment(users[0], users[1])
    s_a.terminate()
    
    with pytest.raises(InvalidInputError) as exc:
        encrypt_e2ee_message(s_a, "Fail")
    assert "terminated session" in str(exc.value)
