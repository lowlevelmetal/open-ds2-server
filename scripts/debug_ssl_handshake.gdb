# debug_ssl_handshake.gdb - Debug SSL handshake in Dead Space 2
#
# This script sets breakpoints on key SSL functions to trace
# what's happening during the certificate verification flow.
#
# Usage: sudo gdb -x debug_ssl_handshake.gdb -p <PID>

set pagination off
set confirm off
set print pretty on

# Key addresses in activation.x86.dll (base 0x795e0000)
# From reverse engineering notes:

echo \n=== Dead Space 2 SSL Handshake Debugger ===\n\n

# Verify patch is applied
echo Checking patch status at 0x795eecec:\n
x/1i 0x795eecec

# Break on the handshake wrapper function (called after SSL_set_verify)
# This is at 0x795efe50
echo \nSetting breakpoint on handshake wrapper (0x795efe50)...\n
break *0x795efe50
commands
    silent
    printf ">>> HANDSHAKE WRAPPER called\n"
    printf "    Argument (ptr): 0x%x\n", *(int*)($esp+4)
    continue
end

# Break on SSL_set_verify (0x795efdb0) - even though we skip it, let's confirm
echo Setting breakpoint on SSL_set_verify (0x795efdb0)...\n
break *0x795efdb0
commands
    silent
    printf ">>> SSL_set_verify called\n"
    printf "    ssl: 0x%x\n", *(int*)($esp+4)
    printf "    mode: %d\n", *(int*)($esp+8)
    printf "    callback: 0x%x\n", *(int*)($esp+12)
    continue
end

# Break on the error path where 0x2a is set (0x795eed03)
echo Setting breakpoint on error path (0x795eed03)...\n
break *0x795eed03
commands
    silent
    printf ">>> ERROR: Certificate rejected! Setting error 0x2a\n"
    printf "    About to set ebx = 0x2a (bad_certificate)\n"
    bt 5
    continue
end

# Break on handshake return (0x795eed08) 
echo Setting breakpoint on handshake return (0x795eed08)...\n
break *0x795eed08
commands
    silent
    printf ">>> HANDSHAKE completed, result in ebx: 0x%x\n", $ebx
    if $ebx == 0
        printf "    SUCCESS!\n"
    else
        printf "    FAILED with error code 0x%x\n", $ebx
    end
    continue
end

# Let's also find ssl_verify_cert_chain or similar
# Search for functions that might be doing verification

echo \nBreakpoints set. Starting debugging...\n
echo Connect to multiplayer now.\n
echo Press Ctrl+C to stop.\n\n

continue
