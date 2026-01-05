#!/usr/bin/env python3
"""
Find active SSL_CTX structures in Dead Space 2 memory and patch them.

SSL_CTX structure layout (OpenSSL 1.0.0b):
- verify_mode at offset 0x420
- verify_callback at offset 0x424

Strategy: Search for memory patterns that look like SSL_CTX structures
"""

# We know:
# - activation.x86.dll code at 0x795e1000-0x79651000
# - .rdata at 0x79651000-0x79678000  
# - .data at 0x79678000-0x7967f000
# - The SSL_CTX struct is allocated dynamically

# SSL_CTX typically has recognizable patterns:
# - method pointer at offset 0x00 (points to SSLv3_method vtable)
# - session cache mode at some offset
# - verify_mode at 0x420

print("To find and patch the SSL_CTX directly, we need to:")
print("1. Find SSL_CTX_new calls to see where ctx pointer is stored")
print("2. Or search data sections for pointers to SSL method structures")
print()
print("Alternative: Restart game with pre-emptive patch using LD_PRELOAD or similar")
print()
print("GDB commands to find SSL_CTX:")
print("  # Search for non-zero verify_mode in potential SSL_CTX locations")
print("  # Look for SSL_CTX allocated in heap - harder to find")
print()
print("Better approach: Patch at SSL_do_handshake level to skip verification")

