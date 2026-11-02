import pytest
from core.x25519 import generate_x25519_key_pair, derive_shared_secret, derive_hkdf_key
from core.exceptions import CryptographicOperationError, InvalidInputError
from core.rsa import generate_rsa_key_pair

def test_x25519_key_agreement():
    alice_priv, alice_pub = generate_x25519_key_pair()
    bob_priv, bob_pub = generate_x25519_key_pair()
    
    # Both parties derive the same secret
    alice_secret = derive_shared_secret(alice_priv, bob_pub)
    bob_secret = derive_shared_secret(bob_priv, alice_pub)
    
    assert alice_secret == bob_secret
    
    # HKDF Derivation mapping
    alice_symmetric = derive_hkdf_key(alice_secret, "Test-Context", 32)
    bob_symmetric = derive_hkdf_key(bob_secret, "Test-Context", 32)
    
    assert alice_symmetric == bob_symmetric
    assert len(alice_symmetric) == 32

def test_x25519_invalid_key_type():
    alice_priv, _ = generate_x25519_key_pair()
    _, rsa_pub = generate_rsa_key_pair(2048)
    
    with pytest.raises(InvalidInputError):
        derive_shared_secret(alice_priv, rsa_pub)
