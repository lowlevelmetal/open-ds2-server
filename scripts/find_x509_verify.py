#!/usr/bin/env python3
"""
Find X509_verify_cert in activation.dll

In OpenSSL 1.0.0, X509_verify_cert:
- Takes X509_STORE_CTX* as single argument
- Returns 1 on success, 0 or -1 on failure
- Is called during SSL handshake to validate server cert

The function references error strings like:
- "unable to get local issuer certificate"
- "self signed certificate"
- "certificate signature failure"

We can find it by looking for the characteristic structure
or by finding X509_STORE_CTX_get_error calls.
"""
import struct

with open('dumps/activation_live_text.bin', 'rb') as f:
    data = f.read()

TEXT_BASE = 0x795e1000

# X509_verify_cert is a complex function (~500-1000 bytes)
# It typically has a loop and many conditional branches

# Let's search for functions that:
# 1. Have a single argument
# 2. Return 0, 1, or -1
# 3. Are of medium complexity

# First, find functions that compare return value against -1 or use X509 error codes
# X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT = 2
# X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN = 19

print("Searching for X509 verification patterns...\n")

# Search for "cmp eax, -1" or "cmp eax, 0xffffffff"
for i in range(len(data) - 10):
    if data[i:i+3] == bytes([0x83, 0xf8, 0xff]):  # cmp eax, -1
        # Look for ret nearby
        for j in range(20):
            if i+3+j < len(data) and data[i+3+j] == 0xc3:
                addr = TEXT_BASE + i
                print(f"cmp eax,-1 at 0x{addr:08x}, ret at +{3+j}")
                break

# Search for error code comparisons  
# cmp dword ptr [reg], 2 or cmp dword ptr [reg], 19
for i in range(len(data) - 10):
    # cmp dword ptr [eax+X], 2 - comparing error code
    if data[i:i+3] == bytes([0x83, 0x78]) and data[i+3] == 0x02:  # cmp [eax+X], 2
        print(f"X509_V_ERR comparison at 0x{TEXT_BASE + i:08x}: cmp [eax+{data[i+2]:02x}], 2")

# Search for functions that have many conditional returns (typical of verify)
# This would be a function with multiple "return X" paths

# Actually, let's find ssl3_get_server_certificate which calls the verify function
# It's typically in ssl/s3_clnt.c

# Look for strings related to certificate handling
print("\nSearching for SSL3 client certificate handling...\n")

# Pattern: Function that calls X509_verify_cert and checks return
# mov eax, <SSL_CTX or X509_STORE_CTX>
# push eax
# call X509_verify_cert
# test eax, eax / cmp eax, 0
# jle error

# Let's find call instructions followed by test eax,eax; jle
call_test_jle = []
for i in range(len(data) - 20):
    if data[i] == 0xe8:  # call
        # Check for test eax,eax after call
        if data[i+5:i+7] == bytes([0x85, 0xc0]):  # test eax, eax
            if data[i+7] in [0x7e, 0x7f, 0x74, 0x75]:  # jle/jg/jz/jnz
                target_rel = struct.unpack('<i', data[i+1:i+5])[0]
                target = (i + 5 + target_rel) & 0xffffffff
                if target < len(data):
                    call_test_jle.append((TEXT_BASE + i, TEXT_BASE + target))

print(f"Found {len(call_test_jle)} call+test+jcc patterns")
print("\nFirst 20 candidates (call target, likely verification functions):")
targets = {}
for call_addr, target_addr in call_test_jle[:100]:
    targets[target_addr] = targets.get(target_addr, 0) + 1

# Sort by frequency
for target, count in sorted(targets.items(), key=lambda x: -x[1])[:20]:
    print(f"  0x{target:08x}: called {count} times with return value check")

