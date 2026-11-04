"""
Automated Testing for Milestone 32: Forward Secrecy & Cryptographic Ratchet.
Validates KDF Key Evolution, Sequence Monotonicity, Out-Of-Order Message Handling, 
and Post-Compromise Security (PCS) recovery.
"""
import pytest
import json
from core.ratchet import RatchetSession, RatchetManager, RatchetStatus, ChainKeyManager
from core.randomness import generate_random_bytes
from core.exceptions import AuthenticationError, InvalidInputError
from core.x25519 import generate_x25519_key_pair, derive_x25519_shared_secret

@pytest.fixture
def ratchet_sessions():
    """Sets up an initial Alice/Bob RatchetSession pair using a root key."""
    root_key = generate_random_bytes(32)
    s_alice = RatchetSession("SESS-123", "Alice", "Bob", root_key, True)
    s_bob = RatchetSession("SESS-123", "Bob", "Alice", root_key, False)
    return s_alice, s_bob

def test_chain_key_evolution():
    """Proves Forward Secrecy: The chain key evolves properly without repeating."""
    chain = ChainKeyManager(generate_random_bytes(32))
    mk1, seq1 = chain.next_message_key()
    ck1 = chain.current_chain_key
    
    mk2, seq2 = chain.next_message_key()
    ck2 = chain.current_chain_key
    
    assert seq1 == 1 and seq2 == 2
    assert mk1 != mk2
    assert ck1 != ck2 # Chain key MUST evolve

def test_ratchet_message_encryption_roundtrip(ratchet_sessions):
    s_alice, s_bob = ratchet_sessions
    msg = "Top Secret Ratchet Message"
    
    pkg = RatchetManager.encrypt_message(s_alice, msg)
    assert pkg["sequence_number"] == 1
    assert pkg["ratchet_generation"] == 1
    
    decrypted = RatchetManager.decrypt_message(s_bob, json.dumps(pkg))
    assert decrypted == msg

def test_strict_replay_rejection(ratchet_sessions):
    s_alice, s_bob = ratchet_sessions
    pkg = RatchetManager.encrypt_message(s_alice, "Test Message")
    pkg_json = json.dumps(pkg)
    
    # First decryption succeeds
    RatchetManager.decrypt_message(s_bob, pkg_json)
    
    # Replay Attack immediately fails
    with pytest.raises(AuthenticationError) as exc:
        RatchetManager.decrypt_message(s_bob, pkg_json)
    assert "already been processed" in str(exc.value).lower()

def test_out_of_order_message_handling(ratchet_sessions):
    s_alice, s_bob = ratchet_sessions
    
    pkg1 = RatchetManager.encrypt_message(s_alice, "Msg 1")
    pkg2 = RatchetManager.encrypt_message(s_alice, "Msg 2")
    pkg3 = RatchetManager.encrypt_message(s_alice, "Msg 3")
    
    # Bob receives Msg 3 first (Network delay simulation)
    # He should store keys for Msg 1 & Msg 2, and decrypt Msg 3 successfully.
    dec3 = RatchetManager.decrypt_message(s_bob, json.dumps(pkg3))
    assert dec3 == "Msg 3"
    assert len(s_bob.rx_chain.skipped_message_keys) == 2
    assert 1 in s_bob.rx_chain.skipped_message_keys
    
    # Bob receives Msg 1 later and decrypts using the stored key
    dec1 = RatchetManager.decrypt_message(s_bob, json.dumps(pkg1))
    assert dec1 == "Msg 1"
    assert 1 not in s_bob.rx_chain.skipped_message_keys # Key consumed

def test_post_compromise_security_recovery(ratchet_sessions):
    s_alice, s_bob = ratchet_sessions
    
    # 1. Simulate Attacker stealing Alice's RAM
    s_alice.simulate_compromise()
    assert s_alice.status == RatchetStatus.COMPROMISED
    
    # 2. PCS Recovery (New Ephemeral Diffie-Hellman)
    bob_priv, bob_pub = generate_x25519_key_pair() # Bob sends new ephemeral
    alice_pub = s_alice.perform_post_compromise_recovery(bob_pub)
    
    s_bob.perform_post_compromise_recovery(alice_pub)
    
    # 3. Assert Generation and Status advanced
    assert s_alice.status == RatchetStatus.RECOVERED
    assert s_alice.generation == 2
    assert s_bob.generation == 2
    assert s_alice.root_key == s_bob.root_key
    
    # 4. Message transmission still works
    pkg = RatchetManager.encrypt_message(s_alice, "PCS Recovery Message")
    dec = RatchetManager.decrypt_message(s_bob, json.dumps(pkg))
    assert dec == "PCS Recovery Message"

def test_tampered_generation_rejection(ratchet_sessions):
    s_alice, s_bob = ratchet_sessions
    pkg = RatchetManager.encrypt_message(s_alice, "Test")
    
    # Attacker attempts to force generation downgrade or mismatch
    pkg["ratchet_generation"] = 2 
    
    with pytest.raises(AuthenticationError) as exc:
        RatchetManager.decrypt_message(s_bob, json.dumps(pkg))
    assert "Generation mismatch" in str(exc.value)
