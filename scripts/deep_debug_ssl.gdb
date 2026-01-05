# deep_debug_ssl.gdb - Deep debugging of SSL handshake
#
# This script traces the entire SSL handshake flow to find
# where exactly the client decides to reject the connection.
#
# Usage: sudo gdb -x deep_debug_ssl.gdb -p <PID>

set pagination off
set confirm off

echo \n=== Deep SSL Handshake Debugger ===\n\n

# First verify our skip patch is in place
echo Verifying patch at 0x795eecec:\n
x/1i 0x795eecec
echo \n

# KEY FUNCTIONS TO TRACE:

# 1. The wrapper that calls handshake (0x795efe50)
# Returns non-zero on error
break *0x795efe50
commands
    silent
    printf "\n>>> [HANDSHAKE START] 0x795efe50 called\n"
    continue
end

# 2. The return from handshake wrapper
# Break at function epilogue area
break *0x795f0509
commands
    silent
    printf ">>> [HANDSHAKE END] returning, eax=0x%x\n", $eax
    continue
end

# 3. SSL_do_handshake or ssl3_connect - we need to find this
# Let's trace calls INSIDE the wrapper

# 4. The call that actually does SSL_connect
# In the wrapper at 0x795efeaf there's a call to 0x795efa10
break *0x795efa10
commands
    silent
    printf ">>> [SSL INNER FUNC] 0x795efa10 called\n"
    continue
end

# 5. Look for ssl3_get_server_certificate equivalent
# This is where certificate is processed on client side
# In our case the CLIENT is Dead Space, receiving OUR cert

# Actually wait - we're debugging the GAME which is the CLIENT
# The game sends ClientHello, receives our ServerHello+Cert
# Then it processes our certificate

# Let's find ssl3_read_bytes or similar
# That would be where incoming data is processed

# 6. The error return path at 0x795eed03 (sets error 0x2a)
break *0x795eed03
commands
    printf "\n>>> [ERROR PATH] About to set error 0x2a!\n"
    printf "    This means certificate was REJECTED\n"
    printf "    Backtrace:\n"
    bt 10
    printf "\n    Registers:\n"
    info registers eax ebx ecx edx esi edi ebp
    printf "\n"
    # Don't continue - let user examine
end

# 7. Trace any CALL instructions inside the handshake function
# This helps us see what sub-functions are called

echo \nBreakpoints set. Key breakpoints:\n
echo   0x795efe50 - Handshake wrapper entry\n
echo   0x795efa10 - Inner SSL function\n  
echo   0x795f0509 - Handshake wrapper exit\n
echo   0x795eed03 - ERROR: Certificate rejected\n
echo \nConnect to multiplayer now.\n
echo The debugger will STOP when error 0x2a is about to be set.\n\n

continue
