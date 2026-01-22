# V-Encrypt

![Kali Linux](https://img.shields.io/badge/Kali-Linux-557C94?logo=kali-linux&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python&logoColor=white)
![Cryptography](https://img.shields.io/badge/Security-Cryptography-red)

## Overview

V-Encrypt enables reliable file encryption and decryption using AES-256 in GCM mode, ensuring both confidentiality and integrity. It supports password-based encryption as well as keyfile-based encryption, making it suitable for personal use, secure file storage, and learning applied cryptography.

## Features

- AES-256-GCM authenticated encryption
- Password-based encryption using PBKDF2 key derivation
- Secure keyfile-based encryption with automatic key generation
- Encrypted file header storing required metadata (filename, salt, nonce, authentication tag)
- Automatic restoration of the original filename and file type during decryption
- Supports encryption of any file format
- Simple and informative command-line interface

## Installation

1. Clone or download this repository
2. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

## Usage

### Command Line Interface

```
python vencrypt.py encrypt <input_file>
python vencrypt.py decrypt <encrypted_file.venc>
python vencrypt.py encrypt <input_file> --password "your_password"
python vencrypt.py decrypt <encrypted_file.venc> --password "your_password"
```

### Examples

Encrypt a file using keyfile method:
```
python vencrypt.py encrypt document.pdf
```

Encrypt a file using password:
```
python vencrypt.py encrypt secret.pdf --password "mypassword123"
```

Decrypt a file using keyfile method:
```
python vencrypt.py decrypt document.pdf.venc
```

Decrypt a file using password:
```
python vencrypt.py decrypt secret.pdf.venc --password "mypassword123"
```

## How It Works

V-Encrypt uses industry-standard cryptographic practices:

1. **Encryption Process**:
   - Generates a cryptographically secure salt and nonce
   - For password-based encryption, derives a 256-bit key using PBKDF2 with 100,000 iterations
   - For keyfile-based encryption, generates a random 256-bit key
   - Encrypts the file using AES-256 in GCM mode
   - Stores metadata (original filename, salt, nonce, and authentication tag) in the file header
   - Saves encrypted file with `.venc` extension

2. **Decryption Process**:
   - Reads the metadata from the file header
   - Recovers the encryption key either from password or keyfile
   - Authenticates and decrypts the file using AES-256-GCM
   - Restores the original file with its correct filename and extension

## Security Notes

- AES-256-GCM provides both confidentiality and authenticity
- PBKDF2 with 100,000 iterations makes brute-force attacks difficult
- Unique salt for each encryption prevents rainbow table attacks
- Random nonce for each encryption ensures semantic security
- Authentication tag in GCM mode detects tampering

## Ethical Use Disclaimer

This software is intended strictly for legitimate and ethical security purposes.
The author, Vision KC, provides this project “as is”, without any warranty. Users are solely responsible for ensuring compliance with applicable laws and regulations. The author assumes no liability for misuse, damage, or unlawful use of this software.
By using V-Encrypt, you agree to use it responsibly and ethically.
By using this tool, you agree to use it ethically and legally, respecting the privacy and rights of others.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

**Vision KC**
- [Github](https://github.com/vision-dev1)
- [Portfolio](https://visionkc.com.np)
