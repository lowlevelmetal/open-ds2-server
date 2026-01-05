#!/usr/bin/env python3
"""
Find SSL verification patterns - more thorough search
"""

# Read the text section dump
with open('dumps/activation_live_text.bin', 'rb') as f:
    data = f.read()

TEXT_BASE = 0x795e1000

# Search for various SSL_CTX structure offsets
# The verify fields could be at different offsets depending on compile options
# Typical range: 0x5c to 0x80

print("Searching for verify field writes at various offsets...")
for offset in range(0x50, 0x90, 4):  # Check offsets from 0x50 to 0x8c
    found = False
    for i in range(len(data) - 10):
        # mov [eax+offset], ecx
        if data[i:i+2] == bytes([0x89, 0x48]) and data[i+2] == offset:
            if not found:
                print(f"\nOffset 0x{offset:02x}:")
                found = True
            print(f"  0x{TEXT_BASE + i:08x}: mov [eax+0x{offset:02x}], ecx")
        # mov [eax+offset], edx  
        elif data[i:i+2] == bytes([0x89, 0x50]) and data[i+2] == offset:
            if not found:
                print(f"\nOffset 0x{offset:02x}:")
                found = True
            print(f"  0x{TEXT_BASE + i:08x}: mov [eax+0x{offset:02x}], edx")

# Search for push 1 followed by push 0 (common pattern for SSL_CTX_set_verify call)
print("\n\nSearching for 'push 1; push 0' patterns (verify mode setup):")
count = 0
for i in range(len(data) - 20):
    if data[i:i+4] == bytes([0x6a, 0x01, 0x6a, 0x00]):  # push 1; push 0
        # Check if there's a call nearby
        for j in range(5, 15):
            if data[i+4+j] == 0xe8:  # call rel32
                count += 1
                print(f"  0x{TEXT_BASE + i:08x}: push 1; push 0 (call at +{4+j})")
                break
            elif data[i+4+j] == 0xff and data[i+4+j+1] in [0xd0, 0xd1, 0xd2, 0xd3, 0xd6, 0xd7]:  # call reg
                count += 1  
                print(f"  0x{TEXT_BASE + i:08x}: push 1; push 0 (call reg at +{4+j})")
                break
        if count >= 20:
            print("  ... (truncated)")
            break

# Search for "return 1 unconditionally" small functions (potential verify callback bypass)
print("\n\nSearching for small 'return 1' functions:")
for i in range(len(data) - 10):
    # xor eax,eax; inc eax; ret  OR  mov eax,1; ret
    if data[i:i+4] == bytes([0x33, 0xc0, 0x40, 0xc3]):  # xor eax,eax; inc eax; ret
        print(f"  0x{TEXT_BASE + i:08x}: xor eax,eax; inc eax; ret")
    elif data[i:i+6] == bytes([0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]):  # mov eax,1; ret
        print(f"  0x{TEXT_BASE + i:08x}: mov eax,1; ret")

