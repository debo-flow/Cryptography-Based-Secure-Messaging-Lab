"""
Encoding and Decoding Engine.
"""
import base64
import binascii
from .exceptions import EncodingError

def text_to_bytes(text: str) -> bytes:
    try: return text.encode('utf-8')
    except UnicodeEncodeError as e: raise EncodingError(f"Failed to encode string to UTF-8: {str(e)}")

def bytes_to_text(data: bytes) -> str:
    try: return data.decode('utf-8')
    except UnicodeDecodeError as e: raise EncodingError(f"Failed to decode bytes to UTF-8: {str(e)}")

def bytes_to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def b64_to_bytes(b64_str: str) -> bytes:
    try: return base64.b64decode(b64_str, validate=True)
    except binascii.Error as e: raise EncodingError(f"Invalid Base64 input: {str(e)}")

def bytes_to_hex(data: bytes) -> str:
    return data.hex()

def hex_to_bytes(hex_str: str) -> bytes:
    try: return bytes.fromhex(hex_str)
    except ValueError as e: raise EncodingError(f"Invalid Hexadecimal input: {str(e)}")
