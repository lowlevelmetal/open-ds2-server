# Trace SSL handshake by breaking on recv after connect
# This script sets breakpoints to catch the TLS handshake

set pagination off
set confirm off
set print elements 100

# Break when recv is called - this catches incoming SSL handshake data
# The SSL server_hello will contain the certificate
catch syscall recvfrom

# Commands to run at breakpoint
commands
  # Check if this looks like SSL data (0x16 = handshake, 0x03 0x00 = SSLv3)
  # Print the first few bytes of the received data
  bt 5
  continue
end

echo Breakpoint on recvfrom syscall set\n
echo Now connect to multiplayer in the game...\n
continue
