# trace_socket.gdb - Trace socket operations to find SSL code
#
# Since SSL_set_verify breakpoints don't trigger, let's trace
# the actual socket send/recv to find where SSL is implemented.
#
# Usage: sudo gdb -x trace_socket.gdb -p <PID>

set pagination off
set confirm off

echo \n=== Socket Tracer for SSL Discovery ===\n\n

# Find ws2_32.dll send function
# In Wine, ws2_32!send wraps the actual send syscall

# Let's break on any send to our server port
# Server is on 127.0.0.1:10041 (Blaze SSL) or 42127 (Redirector)

# First let's find where in memory ws2_32.dll is
echo Looking for ws2_32.dll...\n
shell grep ws2_32 /proc/$PPID/maps 2>/dev/null || echo "ws2_32 not found via shell"

# We need to find the actual SSL_write or send call
# Let's trace activation.dll's exports for SSL functions

# From our research, activation.dll has OpenSSL statically linked
# The base is 0x795e0000, .text at 0x795e1000

# Let's set a breakpoint on SSL_write - search for the function
# SSL_write in OpenSSL 1.0 typically has a signature pattern

# For now, let's try to catch ANY call from activation.dll to 
# networking functions by breaking on common patterns

# The socket send should eventually be called
# Let's find the pattern for ClientHello send

echo \nSetting breakpoint on SSL error path we know...\n

# We know 0x795eed03 sets error 0x2a - but this never triggered either
# This means the error happens elsewhere

# Let's try a different approach - find SSL_read/SSL_write
# These MUST be called during SSL communication

# SSL_write pattern search - let's find functions that access
# ssl->method->ssl_write (at certain offset)

echo \nLet's trace the actual connection...\n
echo Looking for socket operations in activation.dll range...\n

# Set catchpoint on syscalls related to networking
# This is a bit heavy but will show us exactly what's happening
catch syscall sendto
commands
    silent
    printf ">>> sendto syscall from: "
    x/1i $pc
    # Check if it's from activation.dll range (0x795e0000-0x79680000)
    if $pc >= 0x795e0000 && $pc < 0x79680000
        printf "    FROM ACTIVATION.DLL!\n"
        bt 3
    end
    continue
end

catch syscall recvfrom  
commands
    silent
    printf ">>> recvfrom syscall from: "
    x/1i $pc
    continue
end

echo \nCatchpoints set on sendto/recvfrom syscalls.\n
echo Connect to multiplayer now.\n
echo We'll see where the SSL data is sent from.\n\n

continue
