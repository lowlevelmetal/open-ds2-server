# GDB script to patch SSL certificate verification in live Dead Space 2 process
# Run with: sudo gdb -q -batch -x scripts/patch_ssl_live.gdb -p <PID>

printf "Patching SSL_CTX_set_verify at 0x795efd90...\n"
printf "Original bytes at 0x795efd94: "
x/4bx 0x795efd94

# Replace: mov ecx,[esp+8]; mov edx,[esp+12]
# With:    xor ecx,ecx; xor edx,edx
set {char}0x795efd94 = 0x31
set {char}0x795efd95 = 0xc9
set {char}0x795efd96 = 0x31
set {char}0x795efd97 = 0xd2

printf "Patched bytes at 0x795efd94: "
x/4bx 0x795efd94

printf "\nPatching SSL_set_verify at 0x795efdb0...\n"
printf "Original bytes at 0x795efdb4: "
x/4bx 0x795efdb4

set {char}0x795efdb4 = 0x31
set {char}0x795efdb5 = 0xc9
set {char}0x795efdb6 = 0x31
set {char}0x795efdb7 = 0xd2

printf "Patched bytes at 0x795efdb4: "
x/4bx 0x795efdb4

printf "\nDone! SSL certificate verification has been disabled.\n"
printf "SSL_CTX_set_verify and SSL_set_verify now always set mode=0 (SSL_VERIFY_NONE)\n"
