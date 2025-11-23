"""
V-Encrypt Utility Functions
Author: Vision KC
GitHub: github.com/vision-dev1
"""

import os
import hashlib
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend


def validate_file(file_path):
    """Check if a file exists and is accessible."""
    return os.path.isfile(file_path) and os.access(file_path, os.R_OK)


def generate_salt(length=16):
    """Generate a cryptographically secure salt."""
    return os.urandom(length)


def generate_nonce(length=12):
    """Generate a cryptographically secure nonce for GCM mode."""
    return os.urandom(length)


def derive_key_from_password(password, salt, key_length=32):
    """
    Derive a key from a password using PBKDF2.
    
    Args:
        password (str): The password to derive key from
        salt (bytes): Salt for key derivation
        key_length (int): Length of derived key in bytes (default 32 for AES-256)
        
    Returns:
        bytes: Derived key
    """
    # Convert password to bytes if it's a string
    if isinstance(password, str):
        password = password.encode('utf-8')
    
    # Use PBKDF2 with SHA256
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=key_length,
        salt=salt,
        iterations=100000,  # Standard recommendation
        backend=default_backend()
    )
    
    key = kdf.derive(password)
    return key


def hash_file(filepath):
    """
    Generate SHA-256 hash of a file.
    
    Args:
        filepath (str): Path to the file
        
    Returns:
        str: Hexadecimal representation of the hash
    """
    sha256_hash = hashlib.sha256()
    with open(filepath, "rb") as f:
        # Read and update hash string value in blocks of 4K
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()