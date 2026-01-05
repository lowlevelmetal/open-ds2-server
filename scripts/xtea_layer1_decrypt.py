#!/usr/bin/env python3
"""
XTEA Layer 1 Decryptor for activation.x86.dll

This script decrypts the first layer of protection in the DLL.
The S3 section contains encrypted code that is decrypted at runtime
using a modified XTEA stream cipher.

Algorithm Details:
- XTEA stream cipher variant (not CTR mode)
- State (v0, v1, sum) carries over between blocks  
- 32 rounds per 8-byte block
- Key is extracted from stack push operations in the entry stub
- Delta constant: 0x9E3779B9 (standard XTEA)

Author: Reverse Engineering Analysis
Date: January 4, 2026
"""

import struct
import sys
import os

# XTEA key extracted from entry stub pushes (reordered as stored in local vars)
XTEA_KEY = [0x408ec6b5, 0xe2e4d222, 0x0614b34a, 0xf6bd5ec7]

# XTEA delta constant
DELTA = 0x9E3779B9

# Number of rounds
NUM_ROUNDS = 32

# Encrypted data parameters
ENCRYPTED_OFFSET = 0x1F3  # Offset into S3 section
ENCRYPTED_SIZE = 0x56D087  # Size to decrypt


def xtea_stream_decrypt(data: bytes, key: list, num_rounds: int = 32) -> bytes:
    """
    XTEA stream cipher decryption.
    
    Unlike standard XTEA CTR mode, this variant maintains state across blocks.
    The XTEA algorithm is run in encryption direction to generate keystream.
    
    Args:
        data: Encrypted data bytes
        key: List of 4 32-bit key words
        num_rounds: Number of XTEA rounds (default 32)
    
    Returns:
        Decrypted data bytes
    """
    v0, v1, sum_val = 0, 0, 0
    decrypted = bytearray()
    offset = 0
    
    while offset < len(data):
        # Generate keystream using XTEA encryption
        for _ in range(num_rounds):
            v0 = (v0 + (((v1 << 4 ^ v1 >> 5) + v1) ^ (sum_val + key[sum_val & 3]))) & 0xFFFFFFFF
            sum_val = (sum_val + DELTA) & 0xFFFFFFFF
            v1 = (v1 + (((v0 << 4 ^ v0 >> 5) + v0) ^ (sum_val + key[(sum_val >> 11) & 3]))) & 0xFFFFFFFF
        
        # XOR with encrypted data
        if offset + 4 <= len(data):
            enc_v0 = struct.unpack_from('<I', data, offset)[0]
            dec_v0 = enc_v0 ^ v0
            decrypted.extend(struct.pack('<I', dec_v0))
        offset += 4
        
        if offset + 4 <= len(data):
            enc_v1 = struct.unpack_from('<I', data, offset)[0]
            dec_v1 = enc_v1 ^ v1
            decrypted.extend(struct.pack('<I', dec_v1))
        offset += 4
    
    return bytes(decrypted)


def decrypt_layer1(dll_path: str, output_path: str) -> bool:
    """
    Decrypt layer 1 of the packed DLL.
    
    Args:
        dll_path: Path to the packed DLL
        output_path: Path to save decrypted data
        
    Returns:
        True if successful, False otherwise
    """
    try:
        import pefile
    except ImportError:
        print("Error: pefile module required. Install with: pip install pefile")
        return False
    
    print(f"[*] Loading DLL: {dll_path}")
    pe = pefile.PE(dll_path)
    
    # Find S3 section
    s3_data = None
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
        if name == 'S3':
            s3_data = section.get_data()
            print(f"[*] Found S3 section: {len(s3_data)} bytes")
            break
    
    if s3_data is None:
        print("Error: S3 section not found")
        return False
    
    # Extract encrypted region
    print(f"[*] Encrypted region: offset 0x{ENCRYPTED_OFFSET:X}, size 0x{ENCRYPTED_SIZE:X}")
    encrypted_data = bytes(s3_data[ENCRYPTED_OFFSET:ENCRYPTED_OFFSET + ENCRYPTED_SIZE])
    
    # Decrypt
    print(f"[*] Decrypting with XTEA stream cipher...")
    print(f"    Key: {[hex(k) for k in XTEA_KEY]}")
    
    decrypted = xtea_stream_decrypt(encrypted_data, XTEA_KEY, NUM_ROUNDS)
    
    # Save output
    print(f"[*] Saving decrypted data to: {output_path}")
    with open(output_path, 'wb') as f:
        f.write(decrypted)
    
    print(f"[+] Decrypted {len(decrypted)} bytes")
    print(f"[*] First 64 bytes: {decrypted[:64].hex()}")
    
    return True


def main():
    if len(sys.argv) < 2:
        script_dir = os.path.dirname(os.path.abspath(__file__))
        dll_path = os.path.join(script_dir, '..', 'bin', 'activation.x86.dll')
        output_path = os.path.join(script_dir, '..', 'decrypted_layer1.bin')
    else:
        dll_path = sys.argv[1]
        output_path = sys.argv[2] if len(sys.argv) > 2 else 'decrypted_layer1.bin'
    
    if not os.path.exists(dll_path):
        print(f"Error: DLL not found: {dll_path}")
        sys.exit(1)
    
    success = decrypt_layer1(dll_path, output_path)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
