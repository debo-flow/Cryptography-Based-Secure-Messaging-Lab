import pytest
from core.public_key_manager import (
    serialize_public_key, serialize_private_key, 
    load_public_key, load_private_key, get_public_key_fingerprint,
    inspect_key
)
from core.x25519 import generate_x25519_key_pair
from core.exceptions import KeySerializationError, InvalidInputError

def test_private_key_requires_password():
    priv, pub = generate_x25519_key_pair()
    
    with pytest.raises(InvalidInputError):
        serialize_private_key(priv, "")

def test_private_key_wrong_password():
    priv, pub = generate_x25519_key_pair()
    pem = serialize_private_key(priv, "CorrectPass")
    
    with pytest.raises(KeySerializationError):
        load_private_key(pem, "WrongPass")

def test_fingerprint_generation_and_inspection():
    priv, pub = generate_x25519_key_pair()
    fp1 = get_public_key_fingerprint(pub)
    
    meta = inspect_key(pub)
    assert meta["algorithm"] == "X25519"
    assert meta["public_fingerprint"] == fp1
    
    # Inspecting private key should extract public fingerprint safely
    priv_meta = inspect_key(priv)
    assert priv_meta["public_fingerprint"] == fp1
    assert "SECRET" in priv_meta["key_classification"]
