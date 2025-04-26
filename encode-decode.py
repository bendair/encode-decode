#!/usr/bin/env python3
"""
A simple reversible string encoder/decoder without any third-party libraries.

Usage:
    # Encode a string:
    python encode-decode.py encode --key mySecret "your text here"

    # Decode a token:
    python encode-decode.py decode --key mySecret "token_here"
"""
import argparse
import base64
import sys


def xor_bytes(data: bytes, key: bytes) -> bytes:
    """XOR data with key (repeating if necessary)."""
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def encode_string(plaintext: str, secret: str) -> str:
    """Encode plaintext using XOR with secret and return URL-safe Base64."""
    data = plaintext.encode('utf-8')
    key = secret.encode('utf-8')
    xored = xor_bytes(data, key)
    token = base64.urlsafe_b64encode(xored).decode('utf-8')
    return token


def decode_string(token: str, secret: str) -> str:
    """Decode token from URL-safe Base64 and reverse XOR with secret."""
    try:
        xored = base64.urlsafe_b64decode(token.encode('utf-8'))
    except base64.binascii.Error:
        print('Error: Invalid token for Base64 decoding.', file=sys.stderr)
        sys.exit(1)
    key = secret.encode('utf-8')
    data = xor_bytes(xored, key)
    try:
        return data.decode('utf-8')
    except UnicodeDecodeError:
        print('Error: Decoded bytes are not valid UTF-8.', file=sys.stderr)
        sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description="Reversible encoder/decoder using XOR and Base64.")
    sub = parser.add_subparsers(dest='command', required=True)

    # Encode subcommand
    p_enc = sub.add_parser('encode', help='Encode a string')
    p_enc.add_argument('--key', required=True, help='Secret key for encoding')
    p_enc.add_argument('text', help='Plaintext to encode')

    # Decode subcommand
    p_dec = sub.add_parser('decode', help='Decode a token')
    p_dec.add_argument('--key', required=True, help='Secret key for decoding')
    p_dec.add_argument('token', help='Token to decode')

    args = parser.parse_args()
    if args.command == 'encode':
        print(encode_string(args.text, args.key))
    elif args.command == 'decode':
        print(decode_string(args.token, args.key))

if __name__ == '__main__':
    main()
