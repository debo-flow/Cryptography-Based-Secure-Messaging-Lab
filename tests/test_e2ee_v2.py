"""
Automated Testing for Milestone 31: Advanced E2EE Architecture.
Validates Identity Binding, Transcript-Bound Handshakes, Directional Keys, and Strict Replay Protection.
"""
import pytest
import json
from core.e2ee_v2 import E2EEIdentityV2, HandshakeEngineV2, MessageEngineV2, SessionState
from core.exceptions import AuthenticationError, InvalidInputError

@pytest.fixture
def identities():
    return E2EEIdentityV2("Alice"), E2EEIdentityV2("Bob")

def test_handshake_and_directional_keys(identities):
    alice, bob = identities
    s_alice, s_bob = HandshakeEngineV2.execute_handshake(alice, bob)
    
    assert s_alice.state == SessionState.ACTIVE
    assert s_bob.state == SessionState.ACTIVE
    
    # Prove keys are directional and isolated
    assert s_alice.tx_key != s_alice.rx_key
    assert s_bob.tx_key != s_bob.rx_key
    
    # Prove Alice's TX is Bob's RX
    assert s_alice.tx_key == s_bob.rx_key
    assert s_alice.rx_key == s_bob.tx_key

def test_message_encryption_roundtrip(identities):
    alice, bob = identities
    s_alice, s_bob = HandshakeEngineV2.execute_handshake(alice, bob)
    
    msg = "Strictly Authenticated Message"
    pkg = MessageEngineV2.encrypt_message(s_alice, msg, "ChaCha20-Poly1305")
    
    assert pkg["envelope_version"] == "V2.0"
    assert pkg["direction"] == "I->R"
    
    decrypted = MessageEngineV2.decrypt_message(s_bob, json.dumps(pkg))
    assert decrypted == msg

def test_strict_replay_protection(identities):
    alice, bob = identities
    s_alice, s_bob = HandshakeEngineV2.execute_handshake(alice, bob)
    
    pkg = MessageEngineV2.encrypt_message(s_alice, "One-Time Message")
    pkg_str = json.dumps(pkg)
    
    # First decryption succeeds
    MessageEngineV2.decrypt_message(s_bob, pkg_str)
    
    # Second decryption of the EXACT SAME package fails immediately
    with pytest.raises(AuthenticationError) as exc:
        MessageEngineV2.decrypt_message(s_bob, pkg_str)
    
    assert "Replay Attack" in str(exc.value)

def test_aead_tampering_rejection(identities):
    alice, bob = identities
    s_alice, s_bob = HandshakeEngineV2.execute_handshake(alice, bob)
    
    pkg = MessageEngineV2.encrypt_message(s_alice, "Important Data")
    
    # Attack: Tamper with Authenticated Metadata
    pkg["sequence_number"] = 9999
    
    with pytest.raises(AuthenticationError):
        MessageEngineV2.decrypt_message(s_bob, json.dumps(pkg))
