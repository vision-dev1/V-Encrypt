"""
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
    with open(input_file_path, 'rb') as f:
        plaintext = f.read()
    
    original_filename = os.path.basename(input_file_path)
    filename_bytes = original_filename.encode('utf-8')
    filename_length = len(filename_bytes)
    
    salt = generate_salt()
    nonce = generate_nonce()
    
    if password:
        key = derive_key_from_password(password, salt)
    else:
        key = os.urandom(32)
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    tag = encryptor.tag
    
    header = struct.pack('<I', filename_length) + filename_bytes + salt + nonce + tag
    
    output_file_path = input_file_path + '.venc'
    with open(output_file_path, 'wb') as f:
        f.write(header)
        f.write(ciphertext)
    
    if not password:
        keyfile_path = input_file_path + '.key'
        with open(keyfile_path, 'wb') as f:
            f.write(salt + key)
    
    return output_file_path


def decrypt_file(input_file_path, password=None):
    with open(input_file_path, 'rb') as f:
        data = f.read()
    
    filename_length = struct.unpack('<I', data[:4])[0]
    filename_bytes = data[4:4+filename_length]
    original_filename = filename_bytes.decode('utf-8')
    
    salt_start = 4 + filename_length
    salt = data[salt_start:salt_start+16]
    
    nonce_start = salt_start + 16
    nonce = data[nonce_start:nonce_start+12]
    
    tag_start = nonce_start + 12
    tag = data[tag_start:tag_start+16]
    
    ciphertext_start = tag_start + 16
    ciphertext = data[ciphertext_start:]
    
    if password:
        key = derive_key_from_password(password, salt)
    else:
        keyfile_path = input_file_path.replace('.venc', '') + '.key'
        if not os.path.exists(keyfile_path):
            raise FileNotFoundError(f"Keyfile not found: {keyfile_path}")
        
        with open(keyfile_path, 'rb') as f:
            keyfile_data = f.read()
            if len(keyfile_data) != 48:
                raise ValueError("Invalid keyfile format")
            
            stored_salt = keyfile_data[:16]
            if stored_salt != salt:
                raise ValueError("Keyfile doesn't match encrypted file")
            
            key = keyfile_data[16:]
    
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    try:
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    except Exception:
        raise ValueError("Decryption failed. Wrong password or corrupted file.")
    
    output_dir = os.path.dirname(input_file_path)
    if output_dir:
        output_file_path = os.path.join(output_dir, original_filename)
    else:
        output_file_path = original_filename
    
    with open(output_file_path, 'wb') as f:
        f.write(plaintext)
    
    return output_file_path
