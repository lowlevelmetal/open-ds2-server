#!/bin/bash
# patch_and_trace_ssl.sh - Set breakpoint on SSL_set_verify to find SSL pointer
#
# When the game calls SSL_set_verify(ssl, mode, callback), we:
# 1. Capture the ssl pointer from first argument
# 2. Patch ssl+0x428 (verify_mode) = 0
# 3. Patch ssl+0x42c (verify_callback) = 0
# 4. Let the function complete (but our patch zeroes the values)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PID=$(pgrep -f deadspace2.exe | head -1)
if [ -z "$PID" ]; then
    echo "Dead Space 2 not running"
    exit 1
fi

echo "Found Dead Space 2 (PID: $PID)"
echo ""
echo "Creating GDB script to intercept SSL_set_verify..."

# Create the GDB script
cat > /tmp/intercept_ssl.gdb << 'EOF'
# intercept_ssl.gdb - Intercept SSL_set_verify and capture SSL pointer

set pagination off
set confirm off

# SSL_set_verify is at 0x795efdb0
# Already patched to:
#   mov eax,[esp+4]    ; ssl pointer in eax
#   xor ecx,ecx        ; mode = 0
#   xor edx,edx        ; callback = 0
#   nop; nop; nop; nop
#   mov [eax+0x428],ecx ; store verify_mode
#   mov [eax+0x42c],edx ; store verify_callback

# Set breakpoint AFTER the function writes to the SSL structure
# At 0x795efdc5 (the ret instruction)
break *0x795efdc5
commands
    silent
    # EAX still contains ssl pointer from function entry
    printf "SSL_set_verify called, SSL* = 0x%x\n", $eax
    
    # Show what was written
    printf "  verify_mode (ssl+0x428) = %d\n", *(int*)($eax + 0x428)
    printf "  verify_callback (ssl+0x42c) = 0x%x\n", *(int*)($eax + 0x42c)
    
    # Force zero values in case something else set them
    set *(int*)($eax + 0x428) = 0
    set *(int*)($eax + 0x42c) = 0
    
    printf "  -> Patched to 0,0\n"
    continue
end

# Also intercept SSL_CTX_set_verify at 0x795efd90 (ret at 0x795efdac)
break *0x795efdac
commands
    silent
    printf "SSL_CTX_set_verify called, SSL_CTX* = 0x%x\n", $eax
    printf "  verify_mode (ctx+0x420) = %d\n", *(int*)($eax + 0x420)
    printf "  verify_callback (ctx+0x424) = 0x%x\n", *(int*)($eax + 0x424)
    
    # Force zero values
    set *(int*)($eax + 0x420) = 0
    set *(int*)($eax + 0x424) = 0
    
    printf "  -> Patched to 0,0\n"
    continue
end

echo Breakpoints set on SSL_set_verify and SSL_CTX_set_verify\n
echo Now attempting multiplayer connection...\n
continue
EOF

echo "Running GDB with interception..."
echo "This will intercept ALL calls to SSL_set_verify and SSL_CTX_set_verify"
echo "and force verify_mode=0 and verify_callback=0"
echo ""
echo "Press Ctrl+C to stop when done testing"
echo ""

sudo gdb -q -x /tmp/intercept_ssl.gdb -p $PID
