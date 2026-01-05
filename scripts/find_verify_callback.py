#!/usr/bin/env python3
"""
Find the SSL verify callback function in activation.dll

The verify callback signature is:
int verify_callback(int preverify_ok, X509_STORE_CTX *ctx);

If preverify_ok is 0, the certificate chain is invalid.
The callback can return 1 to accept anyway, or 0 to reject.

A typical verify callback would:
1. Get the error code: X509_STORE_CTX_get_error(ctx)
2. Get the error depth: X509_STORE_CTX_get_error_depth(ctx)
3. Log or decide based on error
4. Return 0 or 1

Search strategy:
- Look for small functions (< 100 bytes)
- That reference X509_STORE_CTX functions
- Or that simply return 0 or 1 based on first argument
"""

with open('dumps/activation_live_text.bin', 'rb') as f:
    data = f.read()

TEXT_BASE = 0x795e1000

# Search for verify callback patterns

# Pattern 1: Function that checks first arg and returns based on it
# mov eax, [esp+4] ; get preverify_ok
# test eax, eax
# jz fail
# mov eax, 1
# ret
# fail: xor eax, eax; ret

# Pattern 2: Function that always returns 0 (reject)
# xor eax, eax
# ret
# This would be at function start

# Pattern 3: Function that always returns 1 (accept)  
# Already found many of these

# Let's look for functions that take 2 args (8 bytes) and access them
print("Looking for potential verify callback patterns...\n")

# Search for "test arg, arg; conditional ret"
for i in range(len(data) - 20):
    # Check for function prologue or direct arg access
    if data[i:i+4] == bytes([0x8b, 0x44, 0x24, 0x04]):  # mov eax, [esp+4]
        # Look for test eax, eax nearby
        for j in range(4, 15):
            if data[i+j:i+j+2] == bytes([0x85, 0xc0]):  # test eax, eax
                # Found test - check if there's a conditional jump
                if data[i+j+2] in [0x74, 0x75]:  # jz or jnz
                    # This is a candidate!
                    # Look for ret at end
                    for k in range(10, 40):
                        if i+j+k < len(data) and data[i+j+k] == 0xc3:
                            print(f"Candidate at 0x{TEXT_BASE + i:08x}:")
                            print(f"  Bytes: {data[i:i+j+k+1].hex()}")
                            print()
                            break
                break

# Also search for functions that start with xor eax,eax; ret (always fail)
print("\nFunctions that always return 0 (potential rejection):")
for i in range(len(data) - 10):
    if data[i:i+4] == bytes([0x33, 0xc0, 0xc3]):  # xor eax,eax; ret
        # Make sure this is a function start (check for alignment)
        if i == 0 or data[i-1] in [0xc3, 0xcc, 0x90, 0x00]:
            print(f"  0x{TEXT_BASE + i:08x}: xor eax,eax; ret")

print("\nFunctions that always return 1 (potential acceptance):")
count = 0
for i in range(len(data) - 10):
    if data[i:i+6] == bytes([0xb8, 0x01, 0x00, 0x00, 0x00, 0xc3]):  # mov eax,1; ret
        if i == 0 or data[i-1] in [0xc3, 0xcc, 0x90, 0x00]:
            count += 1
            if count <= 10:
                print(f"  0x{TEXT_BASE + i:08x}: mov eax,1; ret")
if count > 10:
    print(f"  ... and {count-10} more")

