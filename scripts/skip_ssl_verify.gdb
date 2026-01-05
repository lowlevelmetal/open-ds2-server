# skip_ssl_verify.gdb - Skip SSL_set_verify call entirely
#
# This patch converts a conditional jump (je) to unconditional (jmp)
# which causes the code to ALWAYS skip the SSL_set_verify call.
#
# Original:
#   0x795eecec: je 0x795eed08    (74 1a)  - skip if mode==0 && callback==0
#
# Patched:
#   0x795eecec: jmp 0x795eed08   (eb 1a)  - always skip SSL_set_verify
#
# This is cleaner than patching SSL_set_verify itself because:
# 1. It works even if SSL_CTX was already initialized with verify_mode
# 2. The SSL structure never gets verify settings applied
# 3. Single byte patch

set pagination off

echo === Patching SSL_set_verify skip at 0x795eecec ===\n
echo Changing je (0x74) to jmp (0xeb) to always skip SSL verification\n

# Before
echo Before patch:\n
x/10i 0x795eece7

# Apply patch: change 0x74 (je) to 0xeb (jmp)
set {char}0x795eecec = 0xeb

# After
echo \nAfter patch:\n
x/10i 0x795eece7

echo \n=== Patch Applied ===\n
echo The game will now SKIP calling SSL_set_verify entirely.\n
echo This means the SSL connection will use default verify_mode=0.\n
