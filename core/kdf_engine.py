"""
Advanced Key Derivation Function (KDF) Engine.
Unifies PBKDF2-HMAC-SHA256, Scrypt, and Argon2id behind a standard interface.
Applies safe boundaries to prevent DoS attacks through excessive resource requests.
"""

from typing import Dict, Any
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import argon2
from argon2.low_level import hash_secret_raw, Type

from .exceptions import CryptographicOperationError, InvalidInputError
from .encoding import text_to_bytes
from .randomness import generate_random_bytes

KDF_DERIVED_KEY_LENGTH = 32 # 256 bits for AES-256

# Centralized Registry for KDF capabilities and safe parameter bounds
KDF_REGISTRY: Dict[str, Dict[str, Any]] = {
    "PBKDF2-HMAC-SHA256": {
        "description": "Standard computationally expensive KDF. Vulnerable to GPU brute-forcing.",
        "defaults": {"iterations": 600_000},
        "bounds": {"iterations": {"min": 10_000, "max": 5_000_000}}
    },
    "Scrypt": {
        "description": "Memory-hard KDF designed to resist ASIC/GPU attacks.",
        "defaults": {"n": 1048576, "r": 8, "p": 1},
        "bounds": {
            "n": {"min": 1024, "max": 2**20}, # N must be a power of 2
            "r": {"min": 8, "max": 32},
            "p": {"min": 1, "max": 16}
        }
    },
    "Argon2id": {
        "description": "Modern hybrid memory-and-time-hard KDF. Winner of the Password Hashing Competition.",
        "defaults": {"memory_cost": 65536, "time_cost": 3, "parallelism": 4},
        "bounds": {
            "memory_cost": {"min": 8192, "max": 1048576}, # 8MB to 1GB
            "time_cost": {"min": 1, "max": 20},
            "parallelism": {"min": 1, "max": 16}
        }
    }
}

def generate_kdf_salt(length: int = 16) -> bytes:
    """Generates a cryptographically secure random salt."""
    return generate_random_bytes(length)

def validate_kdf_parameters(algorithm: str, parameters: dict) -> None:
    """Strictly validates KDF parameters to ensure they reside within safe hardware bounds."""
    if algorithm not in KDF_REGISTRY:
        raise InvalidInputError(f"Unsupported KDF algorithm: {algorithm}")
        
    bounds = KDF_REGISTRY[algorithm]["bounds"]
    for param, limits in bounds.items():
        if param not in parameters:
            raise InvalidInputError(f"Missing required parameter '{param}' for {algorithm}.")
        
        val = parameters[param]
        if not isinstance(val, int):
            raise InvalidInputError(f"Parameter '{param}' must be an integer.")
            
        if val < limits["min"] or val > limits["max"]:
            raise InvalidInputError(
                f"Parameter '{param}' ({val}) is outside safe boundaries ({limits['min']} - {limits['max']})."
            )

    if algorithm == "Scrypt":
        n = parameters["n"]
        if (n & (n - 1)) != 0:
            raise InvalidInputError("Scrypt parameter 'n' must be a power of 2.")

def derive_key(password: str, salt: bytes, algorithm: str, parameters: dict) -> bytes:
    """
    Derives a 256-bit encryption key using the specified KDF and validated parameters.
    """
    if not password:
        raise InvalidInputError("Password cannot be empty.")
    if len(salt) < 16:
        raise InvalidInputError("Salt must be at least 16 bytes.")
        
    validate_kdf_parameters(algorithm, parameters)
    
    pass_bytes = text_to_bytes(password)
    
    try:
        if algorithm == "PBKDF2-HMAC-SHA256":
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=KDF_DERIVED_KEY_LENGTH,
                salt=salt,
                iterations=parameters["iterations"],
            )
            return kdf.derive(pass_bytes)
            
        elif algorithm == "Scrypt":
            kdf = Scrypt(
                salt=salt,
                length=KDF_DERIVED_KEY_LENGTH,
                n=parameters["n"],
                r=parameters["r"],
                p=parameters["p"]
            )
            return kdf.derive(pass_bytes)
            
        elif algorithm == "Argon2id":
            # Uses argon2-cffi's low-level binding for raw key extraction
            return hash_secret_raw(
                secret=pass_bytes,
                salt=salt,
                time_cost=parameters["time_cost"],
                memory_cost=parameters["memory_cost"],
                parallelism=parameters["parallelism"],
                hash_len=KDF_DERIVED_KEY_LENGTH,
                type=Type.ID
            )
    except argon2.exceptions.Argon2Error as e:
        raise CryptographicOperationError(f"Argon2id derivation failed: {str(e)}")
    except Exception as e:
        raise CryptographicOperationError(f"KDF Derivation failed: {str(e)}")
