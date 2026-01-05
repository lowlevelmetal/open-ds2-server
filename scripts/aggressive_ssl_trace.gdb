# aggressive_ssl_trace.gdb - Catch ANY call to the handshake wrapper
#
# Since specific paths aren't being hit, let's break on the
# handshake wrapper function itself (0x795efe50) which MUST
# be called for any SSL connection through this OpenSSL.
#
# Usage: sudo gdb -x aggressive_ssl_trace.gdb -p <PID>

set pagination off
set confirm off

# Ignore Wine signals
handle SIGUSR1 noprint nostop
handle SIGPWR noprint nostop

echo \n=== Aggressive SSL Trace ===\n\n

# Break on the HANDSHAKE WRAPPER ENTRY (0x795efe50)
# This function MUST be called for any SSL through activation.dll
echo Setting breakpoint on handshake wrapper ENTRY (0x795efe50)...\n
break *0x795efe50
commands
    printf "\n>>> HANDSHAKE WRAPPER (0x795efe50) CALLED!\n"
    printf "    Return address: 0x%x\n", *(int*)$esp
    printf "    Caller:\n"
    bt 5
    continue
end

# Also break on SSL_connect if it exists
# SSL_connect typically at ssl_lib.c
# Let's find it by breaking on SSL_do_handshake calls

# Break on SSL_set_fd which must be called before connect
echo Setting breakpoint on SSL_set_fd area...\n

# Let's also try the inner function called by handshake wrapper
echo Setting breakpoint on inner SSL function (0x795efa10)...\n
break *0x795efa10
commands
    printf "\n>>> INNER SSL FUNC (0x795efa10) CALLED!\n"
    bt 3
    continue
end

echo \nBreakpoints set with signal handling.\n
echo Connect to multiplayer now.\n\n

continue
