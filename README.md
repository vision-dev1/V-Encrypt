# V-Encrypt

A secure file encryption tool developed by Vision KC.

## Description

V-Encrypt is a Python-based encryption software that uses AES-256 encryption to securely encrypt and decrypt files. It supports both password-based encryption and keyfile-based encryption methods.

## Features

- AES-256 encryption with GCM mode for authenticated encryption
- Password-based encryption using PBKDF2 key derivation
- Automatic key generation for keyfile-based encryption
- Secure storage of metadata (filename, salt, nonce) in encrypted file header
- Automatic restoration of original file format during decryption
- Support for encrypting any file type
- Clean terminal interface with informative messages

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

This tool is intended for legitimate security purposes only. The author, Vision KC, provides this software "as is" without warranty of any kind. Users are solely responsible for ensuring compliance with all applicable laws and regulations. The developer assumes no liability for misuse of this software.

By using this tool, you agree to use it ethically and legally, respecting the privacy and rights of others.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
## Author

**Vision KC**
- GitHub: [vision-dev1](https://github.com/vision-dev1)
- Website: [visionkc.com.np](https://visionkc.com.np)

Made By Vision | Designed by Vision
