"""
Automated Testing for Milestone 20: Secure Message Transmission.
Validates sequence tracking, duplex messaging, and replay/tampering detection.
"""
import pytest
import json
from core.e2ee import UserIdentity
from core.ake import perform_authenticated_key_exchange
from core.transmission import send_secure_message, receive_secure_message
from core.exceptions import InvalidInputError, AuthenticationError

@pytest.fixture(scope="module")
def users():
    return UserIdentity("Alice-Tx"), UserIdentity("Bob-Rx")

@pytest.fixture(scope="module")
def sessions(users):
    alice, bob = users
    return perform_authenticated_key_exchange(alice, bob)

def test_duplex_messaging_and_sequence_tracking(sessions):
    s_alice, s_bob = sessions
    
    assert s_alice.tx_sequence == 0
    assert s_bob.rx_sequence == 0
    
    # Alice to Bob
    pkg1 = send_secure_message(s_alice, "Message 1 to Bob", "AES-256-GCM")
    assert pkg1["sequence_number"] == 1
    assert s_alice.tx_sequence == 1
    
    res1 = receive_secure_message(s_bob, json.dumps(pkg1))
    assert res1 == "Message 1 to Bob"
    assert s_bob.rx_sequence == 1
    
    # Bob to Alice
    pkg2 = send_secure_message(s_bob, "Reply 1 to Alice", "ChaCha20-Poly1305")
    assert pkg2["sequence_number"] == 1
    
    res2 = receive_secure_message(s_alice, json.dumps(pkg2))
    assert res2 == "Reply 1 to Alice"

def test_replay_protection_sequence(sessions):
    s_alice, s_bob = sessions
    
    # Record current valid sequence package
    pkg = send_secure_message(s_alice, "Valid message", "AES-256-GCM")
    
    # Bob successfully receives it
    receive_secure_message(s_bob, json.dumps(pkg))
    
    # Attacker replays exact same message
    with pytest.raises(AuthenticationError) as exc:
        receive_secure_message(s_bob, json.dumps(pkg))
    assert "Replay Attack Detected" in str(exc.value)

def test_tampered_ciphertext(sessions):
    s_alice, s_bob = sessions
    pkg = send_secure_message(s_alice, "Bank transfer $100", "AES-256-GCM")
    
    from core.encoding import b64_to_bytes, bytes_to_b64
    ct = b64_to_bytes(pkg["ciphertext"])
    tampered = bytes([ct[0] ^ 0xFF]) + ct[1:]
    pkg["ciphertext"] = bytes_to_b64(tampered)
    
    with pytest.raises(AuthenticationError):
        receive_secure_message(s_bob, json.dumps(pkg))

def test_empty_message_rejection(sessions):
    s_alice, _ = sessions
    with pytest.raises(InvalidInputError) as exc:
        send_secure_message(s_alice, "")
    assert "empty message" in str(exc.value)
