# find_ssl_path.gdb - Find the ACTUAL SSL code path
#
# The previous patches didn't work because we patched the wrong
# code path. This script sets breakpoints on core SSL functions
# that MUST be called for any SSL connection.
#
# Usage: sudo gdb -x find_ssl_path.gdb -p <PID>

set pagination off
set confirm off

echo \n=== Finding Real SSL Code Path ===\n\n

# These are CORE OpenSSL functions that must be called:

# SSL_connect - client initiates handshake (0x795f0a40 maybe?)
# SSL_new - creates new SSL object
# SSL_set_fd - sets socket for SSL
# SSL_do_handshake - performs handshake

# Let's find SSL_connect by searching for known pattern
# SSL_connect typically calls SSL_do_handshake internally

# From our RE notes:
# SSL_CTX_set_verify: 0x795efd90
# SSL_set_verify: 0x795efdb0

# Let's set breakpoints on these to see if they're called at all
echo Setting breakpoint on SSL_set_verify (0x795efdb0)...\n
break *0x795efdb0
commands
    silent
    printf "\n>>> SSL_set_verify CALLED!\n"
    printf "    ssl: 0x%x\n", *(int*)($esp+4)
    printf "    mode: %d\n", *(int*)($esp+8)  
    printf "    callback: 0x%x\n", *(int*)($esp+12)
    printf "    Caller: "
    x/1i *(int*)$esp
    printf "\n"
    bt 5
    continue
end

echo Setting breakpoint on SSL_CTX_set_verify (0x795efd90)...\n
break *0x795efd90
commands
    silent
    printf "\n>>> SSL_CTX_set_verify CALLED!\n"
    printf "    ctx: 0x%x\n", *(int*)($esp+4)
    printf "    mode: %d\n", *(int*)($esp+8)
    printf "    callback: 0x%x\n", *(int*)($esp+12)
    printf "    Caller: "
    x/1i *(int*)$esp
    bt 5
    continue
end

# Also let's find SSL_connect
# In OpenSSL 1.0, SSL_connect is typically:
#   push edi (or some reg with ssl)
#   call SSL_do_handshake
# And it sets s->method->ssl_connect

# Let's also breakpoint on any function that writes to 
# the ssl->verify_mode at offset 0x428
# The only writer we found was 0x795efdbc
echo Setting breakpoint on verify_mode write (0x795efdbc)...\n
break *0x795efdbc
commands
    silent
    printf "\n>>> Writing to ssl->verify_mode!\n"
    printf "    ssl: 0x%x\n", $eax
    printf "    mode (ecx): %d\n", $ecx
    bt 3
    continue
end

echo \nBreakpoints set on:\n
echo   - SSL_set_verify (0x795efdb0)\n
echo   - SSL_CTX_set_verify (0x795efd90)\n
echo   - verify_mode write (0x795efdbc)\n
echo \nNow connect to multiplayer. If NO breakpoints trigger,\n
echo then the game uses DIFFERENT code for multiplayer SSL!\n\n

continue
