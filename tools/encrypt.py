#!/usr/bin/env python3
"""
AES-256-CBC encrypt a binary file for use with the injector.

Outputs:
  1. The encrypted binary (.bin)
  2. A Rust source snippet with split (XOR) key + IV for embedding

Usage:
    python encrypt.py <input_file> <output_file>
    python encrypt.py --rust <input_file> <output_file>    # also print Rust snippet
"""
import os
import sys


def pad_pkcs7(data: bytes, block_size: int = 16) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def split_secret(secret: bytes) -> tuple[bytes, bytes]:
    """Return (half1, half2) where half1 XOR half2 == `secret`."""
    mask = os.urandom(len(secret))
    return (bytes(a ^ b for a, b in zip(secret, mask)), mask)


def fmt_array(name: str, data: bytes, prefix: str = "    ") -> str:
    """Format a byte array as a Rust const literal (12 bytes/line)."""
    entries_per_line = 12
    lines = []
    for i in range(0, len(data), entries_per_line):
        chunk = data[i:i+entries_per_line]
        line = prefix + ", ".join(f"0x{b:02X}" for b in chunk)
        lines.append(line)
    # Join lines with comma+newline so every line except the last gets `,`
    body = ",\n".join(lines) + ","
    return f"const {name}: [u8; {len(data)}] = [\n{body}\n];"


def encrypt_file(in_path: str, out_path: str) -> tuple[bytes, bytes]:
    # Generate key material
    key = os.urandom(32)
    iv  = os.urandom(16)

    # Read & pad
    with open(in_path, 'rb') as f:
        plain = f.read()
    plain = pad_pkcs7(plain)

    # Encrypt — try pycryptodome first, then cryptography fallback
    try:
        from Crypto.Cipher import AES
        cipher = AES.new(key, AES.MODE_CBC, iv)
        ct = cipher.encrypt(plain)
    except ImportError:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        from cryptography.hazmat.backends import default_backend
        c = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = c.encryptor()
        ct = encryptor.update(plain) + encryptor.finalize()

    with open(out_path, 'wb') as f:
        f.write(ct)

    return key, iv


def print_rust_snippet(key: bytes, iv: bytes):
    half1_k, half2_k = split_secret(key)
    half1_i, half2_i = split_secret(iv)
    print("=" * 72)
    print("Rust key material — paste into src/main.rs:")
    print("=" * 72)
    print()
    print(fmt_array("KEY_HALF_1", half1_k))
    print()
    print(fmt_array("KEY_HALF_2", half2_k))
    print()
    print(fmt_array("IV_HALF_1", half1_i))
    print()
    print(fmt_array("IV_HALF_2", half2_i))
    print()
    print("// Actual key = KEY_HALF_1 XOR KEY_HALF_2")
    print("// Actual IV   = IV_HALF_1   XOR IV_HALF_2")
    print()
    # Also print human-readable hex for reference
    print(f"// For reference — real key: {key.hex()}")
    print(f"// For reference — real IV:  {iv.hex()}")


def main():
    show_rust = False
    args = sys.argv[1:]
    if args and args[0] == "--rust":
        show_rust = True
        args = args[1:]

    if len(args) != 2:
        print(f"Usage: {sys.argv[0]} [--rust] <input_file> <output_file>")
        sys.exit(1)

    key, iv = encrypt_file(args[0], args[1])

    print(f"[+] Encrypted: {args[0]} -> {args[1]}")
    print(f"    Key (hex): {key.hex()}")
    print(f"    IV  (hex): {iv.hex()}")

    if show_rust:
        print_rust_snippet(key, iv)


if __name__ == "__main__":
    main()
