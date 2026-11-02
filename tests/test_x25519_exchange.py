"""
Automated Testing for Milestone 12: X25519 Key Exchange & HKDF Derivation.
Validates Alice-Bob ECDH matching, domain separation, and serialization parameters.
"""
import pytest
import json
from core.x25519 import (
    generate_x25519_key_pair, derive_shared_secret, generate_hkdf_salt,
    derive_encryption_key, derive_authentication_key, derive_application_key
)
from core.session import (
    SessionManager, serialize_exchange_package, deserialize_exchange_package
)
from core.exceptions import InvalidInputError, CryptographicOperationError

def test_alice_bob_shared_secret_equality():
    alice_priv, alice_pub = generate_x25519_key_pair()
    bob_priv, bob_pub = generate_x25519_key_pair()
    
    alice_secret = derive_shared_secret(alice_priv, bob_pub)
    bob_secret = derive_shared_secret(bob_priv, alice_pub)
    
    assert alice_secret == bob_secret

def test_hkdf_domain_separation():
    alice_priv, alice_pub = generate_x25519_key_pair()
    bob_priv, bob_pub = generate_x25519_key_pair()
    
    shared_secret = derive_shared_secret(alice_priv, bob_pub)
    salt = generate_hkdf_salt()
    context = "Test-Session-123"
    
    # 1. Same inputs = Same output
    enc_key_1 = derive_encryption_key(shared_secret, salt, context)
    enc_key_2 = derive_encryption_key(shared_secret, salt, context)
    assert enc_key_1 == enc_key_2
    assert len(enc_key_1) == 32 # 256-bit AES key
    
    # 2. Domain separation ensures Encryption Key != Auth Key
    auth_key = derive_authentication_key(shared_secret, salt, context)
    assert enc_key_1 != auth_key
    
    # 3. Different Context = Different output
    enc_key_diff_context = derive_encryption_key(shared_secret, salt, "Other-Session")
    assert enc_key_1 != enc_key_diff_context
    
    # 4. Different Salt = Different output
    salt2 = generate_hkdf_salt()
    enc_key_diff_salt = derive_encryption_key(shared_secret, salt2, context)
    assert enc_key_1 != enc_key_diff_salt

def test_session_manager_lifecycle():
    sm = SessionManager()
    salt = generate_hkdf_salt()
    
    # Create
    sid = sm.create_session("App-Context", salt)
    assert sid in sm.sessions
    assert sm.get_session(sid)["status"] == "ACTIVE"
    
    # Terminate
    sm.terminate_session(sid)
    assert sm.get_session(sid)["status"] == "TERMINATED"
    assert "terminated_at" in sm.get_session(sid)
    
    # Missing session
    with pytest.raises(InvalidInputError):
        sm.get_session("invalid-id")

def test_exchange_package_serialization():
    priv, pub = generate_x25519_key_pair()
    salt = generate_hkdf_salt()
    context = "App-Context"
    sid = "12345-abcde"
    
    # Serialize
    pkg = serialize_exchange_package(pub, salt, context, sid)
    assert pkg["format_version"] == "1.0"
    assert pkg["algorithm"] == "X25519"
    assert pkg["kdf"] == "HKDF-SHA256"
    assert "public_key" in pkg
    
    # Deserialize
    parsed = deserialize_exchange_package(json.dumps(pkg))
    assert parsed["context"] == context
    assert parsed["session_id"] == sid
    assert parsed["salt"] == salt
    # Ensure the public key was restored correctly
    assert parsed["peer_public_key"].public_bytes(
        encoding=__import__('cryptography').hazmat.primitives.serialization.Encoding.DER,
        format=__import__('cryptography').hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo
    ) == pub.public_bytes(
        encoding=__import__('cryptography').hazmat.primitives.serialization.Encoding.DER,
        format=__import__('cryptography').hazmat.primitives.serialization.PublicFormat.SubjectPublicKeyInfo
    )

def test_invalid_exchange_package():
    with pytest.raises(InvalidInputError):
        deserialize_exchange_package('{"format_version": "9.9"}')
