import pytest
from core.ed25519 import generate_ed25519_key_pair, sign_message, verify_signature
from core.exceptions import AuthenticationError

def test_ed25519_signing_and_verification():
    priv, pub = generate_ed25519_key_pair()
    message = "Important Contract Document."
    
    signature = sign_message(priv, message)
    assert verify_signature(pub, signature, message) is True

def test_ed25519_tampered_message_rejection():
    priv, pub = generate_ed25519_key_pair()
    message = "Pay Alice $100."
    tampered_message = "Pay Alice $900."
    
    signature = sign_message(priv, message)
    
    with pytest.raises(AuthenticationError):
        verify_signature(pub, signature, tampered_message)

def test_ed25519_wrong_key_rejection():
    priv1, _ = generate_ed25519_key_pair()
    _, pub2 = generate_ed25519_key_pair()
    message = "Identity Proof."
    
    signature = sign_message(priv1, message)
    
    with pytest.raises(AuthenticationError):
        verify_signature(pub2, signature, message)
