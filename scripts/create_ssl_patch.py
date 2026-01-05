#!/usr/bin/env python3
"""
Create a patch for activation.x86.dll to disable SSL certificate verification.

Strategy: Patch SSL_set_verify (0x795efdb0) to always set mode=0 (SSL_VERIFY_NONE)

Original code at 0x795efdb0:
    8b 44 24 04    mov eax, [esp+4]   ; ctx/ssl
    8b 4c 24 08    mov ecx, [esp+8]   ; mode
    8b 54 24 0c    mov edx, [esp+12]  ; callback
    89 88 28 04 00 00  mov [eax+0x428], ecx  ; ssl->verify_mode = mode
    89 90 2c 04 00 00  mov [eax+0x42c], edx  ; ssl->verify_callback = callback
    c3             ret

Patched code (set mode=0, callback=0):
    8b 44 24 04    mov eax, [esp+4]   ; ctx/ssl
    31 c9          xor ecx, ecx       ; mode = 0 (SSL_VERIFY_NONE) 
    31 d2          xor edx, edx       ; callback = NULL
    89 88 28 04 00 00  mov [eax+0x428], ecx
    89 90 2c 04 00 00  mov [eax+0x42c], edx
    c3             ret
    
Also patch SSL_CTX_set_verify (0x795efd90) the same way.
"""

# Addresses in memory
SSL_CTX_SET_VERIFY = 0x795efd90
SSL_SET_VERIFY = 0x795efdb0
TEXT_BASE = 0x795e1000

# Calculate file offsets (relative to start of .text section dump)
ssl_ctx_offset = SSL_CTX_SET_VERIFY - TEXT_BASE  # 0xed90
ssl_offset = SSL_SET_VERIFY - TEXT_BASE          # 0xedb0

print("SSL Certificate Verification Bypass Patches")
print("=" * 50)

# Original bytes at SSL_CTX_set_verify (0x795efd90)
# 8b4424048b4c24088b54240c898820040000899024040000c3
original_ctx = bytes.fromhex("8b4424048b4c24088b54240c898820040000899024040000c3")

# Patched: set mode=0, callback=0
# 8b442404 31c9 31d2 898820040000 899024040000 c3
patched_ctx = bytes.fromhex("8b44240431c931d2898820040000899024040000c3")

# Need to pad to same length (original is 24 bytes, patched is 22 bytes)
# Add 2 NOPs at end
patched_ctx = patched_ctx + bytes([0x90, 0x90])

# Original bytes at SSL_set_verify (0x795efdb0)  
# 8b4424048b4c24088b54240c898828040000899028040000c3
original_ssl = bytes.fromhex("8b4424048b4c24088b54240c8988280400008990280400c3")

# Patched: set mode=0, callback=0
patched_ssl = bytes.fromhex("8b44240431c931d2898828040000899028040000c3")
patched_ssl = patched_ssl + bytes([0x90, 0x90])

print(f"\n1. SSL_CTX_set_verify at 0x{SSL_CTX_SET_VERIFY:08x} (file offset 0x{ssl_ctx_offset:x}):")
print(f"   Original: {original_ctx.hex()}")
print(f"   Patched:  {patched_ctx.hex()}")

print(f"\n2. SSL_set_verify at 0x{SSL_SET_VERIFY:08x} (file offset 0x{ssl_offset:x}):")
print(f"   Original: {original_ssl.hex()}")
print(f"   Patched:  {patched_ssl.hex()}")

# Read the live text dump and verify
with open('dumps/activation_live_text.bin', 'rb') as f:
    data = bytearray(f.read())

print(f"\nVerifying current bytes at SSL_CTX_set_verify:")
current_ctx = bytes(data[ssl_ctx_offset:ssl_ctx_offset+24])
print(f"   Current:  {current_ctx.hex()}")
print(f"   Expected: {original_ctx.hex()}")
print(f"   Match: {current_ctx == original_ctx}")

print(f"\nVerifying current bytes at SSL_set_verify:")
current_ssl = bytes(data[ssl_offset:ssl_offset+24])
print(f"   Current:  {current_ssl.hex()}")

# Apply patches
print("\n" + "=" * 50)
print("Creating patched binary...")

data[ssl_ctx_offset:ssl_ctx_offset+24] = patched_ctx
data[ssl_offset:ssl_offset+24] = patched_ssl

with open('dumps/activation_patched_text.bin', 'wb') as f:
    f.write(data)

print("Saved to dumps/activation_patched_text.bin")

# Also create a patch file for live memory patching via GDB
print("\nGDB commands to patch live process:")
print("-" * 50)
print(f"# Patch SSL_CTX_set_verify to force mode=0, callback=0")
print(f"set {{char}}0x{SSL_CTX_SET_VERIFY+4:x} = 0x31")  # xor ecx,ecx
print(f"set {{char}}0x{SSL_CTX_SET_VERIFY+5:x} = 0xc9")
print(f"set {{char}}0x{SSL_CTX_SET_VERIFY+6:x} = 0x31")  # xor edx,edx
print(f"set {{char}}0x{SSL_CTX_SET_VERIFY+7:x} = 0xd2")
print()
print(f"# Patch SSL_set_verify to force mode=0, callback=0")
print(f"set {{char}}0x{SSL_SET_VERIFY+4:x} = 0x31")
print(f"set {{char}}0x{SSL_SET_VERIFY+5:x} = 0xc9")
print(f"set {{char}}0x{SSL_SET_VERIFY+6:x} = 0x31")
print(f"set {{char}}0x{SSL_SET_VERIFY+7:x} = 0xd2")

