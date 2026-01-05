#!/usr/bin/env python3
"""
Find SSL verification code by looking for common patterns
"""

import struct

# Load the text section
with open('dumps/deadspace_text.bin', 'rb') as f:
    text = f.read()

base = 0x00401000

print("=== Searching for SSL_CTX_set_verify pattern ===")
print("Looking for: push 0 (SSL_VERIFY_NONE) followed by call")

# Look for pattern: push 0; push reg/imm; call
# 6a 00 = push 0
# 50-57 = push register
# e8 xx xx xx xx = call

for i in range(len(text) - 10):
    # push 0, push something, call
    if text[i:i+2] == b'\x6a\x00':
        # Check if followed by push and call
        if text[i+2] in [0x50, 0x51, 0x52, 0x53, 0x55, 0x56, 0x57]:
            if text[i+3] == 0xe8:  # call
                addr = base + i
                target = struct.unpack('<i', text[i+4:i+8])[0]
                call_target = (base + i + 8 + target) & 0xffffffff
                print(f"  0x{addr:08x}: push 0; push reg; call 0x{call_target:08x}")
        # Check for push imm32
        elif text[i+2] == 0x68:
            if text[i+7] == 0xe8:  # call
                addr = base + i
                print(f"  0x{addr:08x}: push 0; push imm32; call ...")

print()
print("=== Searching for verify callback function pattern ===")
print("Looking for: cmp eax, 1 / test eax, eax after call (return value check)")

# Pattern: call xxx; test eax, eax; jnz/jz xxx (checking return value)
for i in range(len(text) - 10):
    # test eax, eax; jz/jnz
    if text[i:i+2] == b'\x85\xc0':  # test eax, eax
        if text[i+2] in [0x74, 0x75, 0x0f]:  # jz, jnz, or extended
            # Check if preceded by call
            if i >= 5 and text[i-5] == 0xe8:  # call
                addr = base + i - 5
                # Check context - is this related to certificate?
                ctx = text[max(0, i-20):i+10]
                # Look for push before call that might be SSL-related
                if b'\x68' in text[max(0, i-15):i-5]:  # push imm32 before call
                    pass  # Found potential verify check

print()
print("=== Looking for X.509 certificate chain verification ===")
# Search for patterns related to X509 processing

# Look for comparison with specific error codes
# SSL error 20 = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
# SSL error 21 = X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
# SSL error 19 = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN

for code, name in [(19, "SELF_SIGNED_IN_CHAIN"), (20, "NO_ISSUER_CERT"), (21, "VERIFY_LEAF")]:
    print(f"\nError code {code} ({name}):")
    count = 0
    for i in range(len(text) - 4):
        # cmp reg, imm8
        if text[i] == 0x83 and text[i+1] in [0xf8, 0xf9, 0xfa, 0xfb, 0xfd, 0xfe, 0xff] and text[i+2] == code:
            addr = base + i
            print(f"  0x{addr:08x}: cmp reg, {code}")
            count += 1
            if count > 5: 
                print("  ...")
                break
        # cmp eax, imm8
        if text[i:i+2] == b'\x3c' + bytes([code]):
            addr = base + i
            print(f"  0x{addr:08x}: cmp al, {code}")
            count += 1
            if count > 5:
                print("  ...")
                break

