#!/usr/bin/env python3
"""
Find callers of SSL_CTX_set_verify and SSL_set_verify
"""
import struct

with open('dumps/activation_live_text.bin', 'rb') as f:
    data = f.read()

TEXT_BASE = 0x795e1000

# Target function addresses (relative to text base)
SSL_CTX_set_verify = 0x795efd90 - TEXT_BASE  # 0xed90
SSL_set_verify = 0x795efdb0 - TEXT_BASE       # 0xedb0

print(f"SSL_CTX_set_verify offset: 0x{SSL_CTX_set_verify:x}")
print(f"SSL_set_verify offset: 0x{SSL_set_verify:x}")

print("\nSearching for calls to SSL_CTX_set_verify (0x795efd90)...")
for i in range(len(data) - 5):
    if data[i] == 0xe8:  # call rel32
        # Calculate target
        rel = struct.unpack('<i', data[i+1:i+5])[0]
        target = (i + 5 + rel) & 0xffffffff
        if target == SSL_CTX_set_verify:
            print(f"  Call at 0x{TEXT_BASE + i:08x}")
            # Show context
            start = max(0, i - 20)
            print(f"    Context: {data[start:i+5].hex()}")

print("\nSearching for calls to SSL_set_verify (0x795efdb0)...")
for i in range(len(data) - 5):
    if data[i] == 0xe8:  # call rel32
        rel = struct.unpack('<i', data[i+1:i+5])[0]
        target = (i + 5 + rel) & 0xffffffff
        if target == SSL_set_verify:
            print(f"  Call at 0x{TEXT_BASE + i:08x}")
            start = max(0, i - 20)
            print(f"    Context: {data[start:i+5].hex()}")

