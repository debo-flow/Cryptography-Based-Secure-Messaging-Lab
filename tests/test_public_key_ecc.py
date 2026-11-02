import pytest
from core.ecc import generate_ecc_key_pair, SUPPORTED_CURVES
from core.exceptions import InvalidInputError
from core.public_key_manager import serialize_public_key, load_public_key

def test_ecc_key_generation_and_serialization():
    for curve in SUPPORTED_CURVES.keys():
        priv, pub = generate_ecc_key_pair(curve)
        assert priv is not None
        
        # Test serialization
        pem = serialize_public_key(pub)
        assert "BEGIN PUBLIC KEY" in pem
        
        # Test deserialization
        loaded_pub = load_public_key(pem)
        assert loaded_pub.curve.name == pub.curve.name

def test_invalid_curve_rejection():
    with pytest.raises(InvalidInputError):
        generate_ecc_key_pair("INVALID_CURVE")
