# FIXED GDB script to properly patch SSL certificate verification
# The previous patch was incomplete - we need to NOP out more bytes

printf "Checking current state of SSL_CTX_set_verify...\n"
x/10bx 0x795efd94

printf "\nFixing patch - adding NOPs after xor instructions...\n"

# SSL_CTX_set_verify at 0x795efd90
# Original: 8b4424048b4c24088b54240c898820040000899024040000c3
# We patched bytes 4-7 to: 31c931d2 (xor ecx,ecx; xor edx,edx)
# But bytes 8-11 (8b54240c = mov edx,[esp+12]) remained
# Need to NOP those out: 90909090

set {char}0x795efd98 = 0x90
set {char}0x795efd99 = 0x90
set {char}0x795efd9a = 0x90
set {char}0x795efd9b = 0x90

printf "SSL_CTX_set_verify patched bytes: "
x/12bx 0x795efd94

# SSL_set_verify at 0x795efdb0 - same fix needed
printf "\nFixing SSL_set_verify...\n"
x/10bx 0x795efdb4

set {char}0x795efdb8 = 0x90
set {char}0x795efdb9 = 0x90
set {char}0x795efdba = 0x90
set {char}0x795efdbb = 0x90

printf "SSL_set_verify patched bytes: "
x/12bx 0x795efdb4

printf "\nDisassembling patched SSL_CTX_set_verify:\n"
x/8i 0x795efd90

printf "\nDisassembling patched SSL_set_verify:\n"
x/8i 0x795efdb0

printf "\nPatch complete!\n"
