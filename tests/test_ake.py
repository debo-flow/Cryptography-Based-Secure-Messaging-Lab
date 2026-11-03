"""
Automated Testing for Milestone 19: Secure Key Exchange & Identity Authentication.
Validates Ed25519 signature binding, directional keys, and replay/downgrade protection.
"""
import pytest
import time
from core.e2ee import UserIdentity
from core.ake import (
    generate_ake_nonce, build_canonical_transcript, hash_transcript,
    verify_replay_protection, derive_directional_keys, generate_session_confirmation,
    verify_session_confirmation, _REPLAY_CACHE
)
from core.ed25519 import sign_message, verify_signature
from core.x25519 import derive_x25519_shared_secret, serialize_x25519_public_key
from core.exceptions import AuthenticationError

@pytest.fixture(scope="module")
def users():
    return UserIdentity("Alice-Initiator"), UserIdentity("Bob-Responder")

def test_canonical_transcript_binding(users):
    alice, bob = users
    ts = time.time()
    transcript = build_canonical_transcript(
        "1.0", "session-123", alice.user_id, bob.user_id,
        "ALICE-FP", "BOB-FP", "EPH-ALICE", "EPH-BOB",
        "NONCE-A", "NONCE-B", "X25519-Ed25519-AES256GCM", ts
    )
    t_hash = hash_transcript(transcript)
    
    # Sign and verify
    sig = sign_message(alice.ed25519_priv, transcript)
    assert verify_signature(alice.ed25519_pub, sig, transcript) is True
    
    # Tampering with downgrade attack
    tampered_transcript = build_canonical_transcript(
        "1.0", "session-123", alice.user_id, bob.user_id,
        "ALICE-FP", "BOB-FP", "EPH-ALICE", "EPH-BOB",
        "NONCE-A", "NONCE-B", "X25519-Ed25519-WEAK_CIPHER", ts
    )
    with pytest.raises(AuthenticationError):
        verify_signature(alice.ed25519_pub, sig, tampered_transcript)

def test_replay_protection():
    sid = "unique-replay-test-id"
    ts = time.time()
    
    # First time succeeds
    verify_replay_protection(sid, ts)
    
    # Second time rejects
    with pytest.raises(AuthenticationError) as exc:
        verify_replay_protection(sid, ts)
    assert "already consumed" in str(exc.value)
    
    # Expired rejects
    with pytest.raises(AuthenticationError) as exc:
        verify_replay_protection("new-id", ts - 400)
    assert "Timestamp expired" in str(exc.value)

def test_directional_keys_and_confirmation(users):
    alice, bob = users
    a_sec = derive_x25519_shared_secret(alice.x25519_priv, bob.x25519_pub)
    b_sec = derive_x25519_shared_secret(bob.x25519_priv, alice.x25519_pub)
    
    t_hash = hash_transcript(b"dummy-transcript")
    
    # Derive directional keys
    a_tx, a_rx, a_conf = derive_directional_keys(a_sec, t_hash)
    b_tx, b_rx, b_conf = derive_directional_keys(b_sec, t_hash)
    
    # Alice's Tx == Bob's Rx
    assert a_tx == b_rx
    assert a_rx == b_tx
    assert a_conf == b_conf
    
    # Mutual Confirmation
    a_proof = generate_session_confirmation(a_conf, t_hash, "INITIATOR")
    b_proof = generate_session_confirmation(b_conf, t_hash, "RESPONDER")
    
    # Verify each other's proofs
    verify_session_confirmation(b_conf, t_hash, "INITIATOR", a_proof)
    verify_session_confirmation(a_conf, t_hash, "RESPONDER", b_proof)
