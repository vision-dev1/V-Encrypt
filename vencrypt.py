#!/usr/bin/env python3
"""
V-Encrypt - A secure file encryption tool
Author: Vision KC
GitHub: github.com/vision-dev1
"""

import argparse
import os
import sys
from pathlib import Path

from crypto_core import encrypt_file, decrypt_file
from utils import validate_file


def main():
    parser = argparse.ArgumentParser(
        description="V-Encrypt - Secure File Encryption Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vencrypt.py encrypt input.jpg
  python vencrypt.py decrypt input.venc
  python vencrypt.py encrypt secret.pdf --password "mypassword"
  python vencrypt.py decrypt secret.venc --password "mypassword"
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Encrypt subcommand
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('input_file', help='File to encrypt')
    encrypt_parser.add_argument('--password', '-p', help='Password for encryption (if not provided, a keyfile will be generated)')
    
    # Decrypt subcommand
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('input_file', help='File to decrypt (.venc)')
    decrypt_parser.add_argument('--password', '-p', help='Password for decryption')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    # Validate input file
    if not validate_file(args.input_file):
        print(f"Error: File '{args.input_file}' does not exist or is not accessible.")
        sys.exit(1)
    
    try:
        if args.command == 'encrypt':
            print("Encrypting...")
            output_file = encrypt_file(args.input_file, args.password)
            print(f"File encrypted successfully: {output_file}")
            
        elif args.command == 'decrypt':
            print("Decrypting...")
            output_file = decrypt_file(args.input_file, args.password)
            print(f"File restored successfully: {output_file}")
            
    except Exception as e:
        print(f"Error: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()