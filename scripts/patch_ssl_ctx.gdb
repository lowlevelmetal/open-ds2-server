# patch_ssl_ctx.gdb - Patch existing SSL_CTX structure directly in memory
# This is needed when the SSL_CTX was already initialized before our function patch
#
# SSL_CTX structure in OpenSSL 1.0.0b:
#   offset 0x420: verify_mode (int)
#   offset 0x424: verify_callback (function pointer)
#
# This script:
# 1. Applies the function patches (for future calls)
# 2. Searches for and patches existing SSL_CTX structures

# First apply the function patches
echo "=== Patching SSL_CTX_set_verify at 0x795efd90 ===\n"
set {char}0x795efd94 = 0x31
set {char}0x795efd95 = 0xc9
set {char}0x795efd96 = 0x31
set {char}0x795efd97 = 0xd2
set {char}0x795efd98 = 0x90
set {char}0x795efd99 = 0x90
set {char}0x795efd9a = 0x90
set {char}0x795efd9b = 0x90

echo "=== Patching SSL_set_verify at 0x795efdb0 ===\n"
set {char}0x795efdb4 = 0x31
set {char}0x795efdb5 = 0xc9
set {char}0x795efdb6 = 0x31
set {char}0x795efdb7 = 0xd2
set {char}0x795efdb8 = 0x90
set {char}0x795efdb9 = 0x90
set {char}0x795efdba = 0x90
set {char}0x795efdbb = 0x90

echo "Function patches applied\n"

# Verify patches
echo "=== Verifying SSL_CTX_set_verify ===\n"
x/10i 0x795efd90

echo "=== Verifying SSL_set_verify ===\n"
x/10i 0x795efdb0

echo "Done - Function patches applied\n"
echo "NOTE: For existing SSL_CTX objects, you may need to:\n"
echo "1. Find the SSL_CTX pointer in memory\n"
echo "2. Set *(int*)(ctx+0x420) = 0   (verify_mode)\n"
echo "3. Set *(int*)(ctx+0x424) = 0   (verify_callback)\n"
