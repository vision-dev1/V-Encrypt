"""
V-Encrypt Core Encryption/Decryption Module
Author: Vision KC
GitHub: github.com/vision-dev1
"""

import os
import struct
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from utils import derive_key_from_password, generate_salt, generate_nonce


def encrypt_file(input_file_path, password=None):
    """
    Encrypt a file using AES-256-GCM or password-based encryption.
    
    Args:
        input_file_path (str): Path to the file to encrypt
        password (str, optional): Password for encryption. If None, keyfile method is used.
        
    Returns:
        str: Path to the encrypted file (.venc)
    """
    # Read the input file
    with open(input_file_path, 'rb') as f:
        plaintext = f.read()
    
    # Get original filename for storing in header
    original_filename = os.path.basename(input_file_path)
    filename_bytes = original_filename.encode('utf-8')
    filename_length = len(filename_bytes)
    
    # Generate salt and nonce
    salt = generate_salt()
    nonce = generate_nonce()
    
    # Derive key
    if password:
        key = derive_key_from_password(password, salt)
    else:
        # Generate a random key for keyfile method
        key = os.urandom(32)  # 256 bits
    
    # Create cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    # Encrypt the plaintext
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    
    # Get the authentication tag
    tag = encryptor.tag
    
    # Create the header
    # Header format:
    # 4 bytes: filename length
    # filename_length bytes: filename
    # 16 bytes: salt
    # 12 bytes: nonce
    # 16 bytes: tag
    header = struct.pack('<I', filename_length) + filename_bytes + salt + nonce + tag
    
    # Write encrypted file
    output_file_path = input_file_path + '.venc'
    with open(output_file_path, 'wb') as f:
        f.write(header)
        f.write(ciphertext)
    
    # If using keyfile method, save the key to a file
    if not password:
        keyfile_path = input_file_path + '.key'
        with open(keyfile_path, 'wb') as f:
            f.write(salt + key)
    
    return output_file_path


def decrypt_file(input_file_path, password=None):
    """
    Decrypt a .venc file.
    
    Args:
        input_file_path (str): Path to the encrypted file (.venc)
        password (str, optional): Password for decryption. If None, keyfile method is used.
        
    Returns:
        str: Path to the decrypted file
    """
    # Read the encrypted file
    with open(input_file_path, 'rb') as f:
        data = f.read()
    
    # Parse header
    # Read filename length (4 bytes)
    filename_length = struct.unpack('<I', data[:4])[0]
    
    # Read filename
    filename_bytes = data[4:4+filename_length]
    original_filename = filename_bytes.decode('utf-8')
    
    # Read salt (16 bytes)
    salt_start = 4 + filename_length
    salt = data[salt_start:salt_start+16]
    
    # Read nonce (12 bytes)
    nonce_start = salt_start + 16
    nonce = data[nonce_start:nonce_start+12]
    
    # Read tag (16 bytes)
    tag_start = nonce_start + 12
    tag = data[tag_start:tag_start+16]
    
    # Read ciphertext
    ciphertext_start = tag_start + 16
    ciphertext = data[ciphertext_start:]
    
    # Derive key
    if password:
        key = derive_key_from_password(password, salt)
    else:
        # Load key from keyfile
        keyfile_path = input_file_path.replace('.venc', '') + '.key'
        if not os.path.exists(keyfile_path):
            raise FileNotFoundError(f"Keyfile not found: {keyfile_path}")
        
        with open(keyfile_path, 'rb') as f:
            keyfile_data = f.read()
            if len(keyfile_data) != 48:  # 16 bytes salt + 32 bytes key
                raise ValueError("Invalid keyfile format")
            
            stored_salt = keyfile_data[:16]
            if stored_salt != salt:
                raise ValueError("Keyfile doesn't match encrypted file")
            
            key = keyfile_data[16:]
    
    # Create cipher
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    # Decrypt the ciphertext
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:
        raise ValueError("Decryption failed. Wrong password or corrupted file.")
    
    # Write decrypted file
    # Place the decrypted file in the same directory as the encrypted file
    output_dir = os.path.dirname(input_file_path)
    if output_dir:
        output_file_path = os.path.join(output_dir, original_filename)
    else:
        output_file_path = original_filename
    
    with open(output_file_path, 'wb') as f:
        f.write(plaintext)
    
    return output_file_path