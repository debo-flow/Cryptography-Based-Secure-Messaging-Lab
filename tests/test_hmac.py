"""
Automated Testing for Milestone 17: Advanced Message Authentication (HMAC).
"""
import pytest
import json
import io
from core.hmac_engine import (
    generate_hmac_key, calculate_hmac, verify_hmac, get_key_identifier,
    create_authentication_package, validate_authentication_package,
    authenticate_file, verify_file_authentication, HMAC_SUPPORTED_ALGOS
)
from core.exceptions import InvalidInputError, AuthenticationError
from core.encoding import bytes_to_b64, b64_to_bytes, text_to_bytes

def test_hmac_key_generation_and_identification():
    key = generate_hmac_key(32)
    assert len(key) == 32
    key_id = get_key_identifier(key)
    assert len(key_id) == 16
    assert isinstance(key_id, str)
    
    with pytest.raises(InvalidInputError):
        generate_hmac_key(10) # Too short

@pytest.mark.parametrize("algorithm", HMAC_SUPPORTED_ALGOS)
def test_hmac_matrix_round_trip(algorithm):
    key = generate_hmac_key()
    message = "Integrity check payload."
    
    pkg = create_authentication_package(key, message, algorithm)
    assert pkg["format_version"] == "1.0"
    assert pkg["algorithm"] == algorithm
    assert pkg["key_identifier"] == get_key_identifier(key)
    
    recovered = validate_authentication_package(key, json.dumps(pkg))
    assert recovered == message

def test_hmac_wrong_key_rejection():
    key1 = generate_hmac_key()
    key2 = generate_hmac_key()
    
    pkg = create_authentication_package(key1, "Secret Data", "HMAC-SHA256")
    
    with pytest.raises(AuthenticationError) as exc:
        validate_authentication_package(key2, json.dumps(pkg))
    assert "Key mismatch" in str(exc.value)

def test_hmac_tampered_message_rejection():
    key = generate_hmac_key()
    pkg = create_authentication_package(key, "Send $100 to Alice", "HMAC-SHA256")
    
    # Attack: Tamper with message
    pkg["message"] = bytes_to_b64(text_to_bytes("Send $900 to Alice"))
    
    with pytest.raises(AuthenticationError):
        validate_authentication_package(key, json.dumps(pkg))

def test_hmac_tampered_tag_rejection():
    key = generate_hmac_key()
    pkg = create_authentication_package(key, "Valid message", "HMAC-SHA256")
    
    # Attack: Tamper with tag
    tag_bytes = b64_to_bytes(pkg["authentication_tag"])
    tampered_tag = bytes([tag_bytes[0] ^ 0xFF]) + tag_bytes[1:]
    pkg["authentication_tag"] = bytes_to_b64(tampered_tag)
    
    with pytest.raises(AuthenticationError):
        validate_authentication_package(key, json.dumps(pkg))

def test_file_hmac_streaming():
    key = generate_hmac_key()
    file_data = b"Simulated binary file content."
    f_stream = io.BytesIO(file_data)
    
    pkg = authenticate_file(key, f_stream, "HMAC-SHA384")
    assert pkg["authentication_type"] == "File-HMAC"
    
    # Verify exact stream
    f_verify = io.BytesIO(file_data)
    assert verify_file_authentication(key, f_verify, json.dumps(pkg)) == "FILE_AUTHENTICATED"
    
    # Verify tampered stream fails
    f_tamper = io.BytesIO(b"Simulated binary file content. Tampered.")
    with pytest.raises(AuthenticationError):
        verify_file_authentication(key, f_tamper, json.dumps(pkg))
