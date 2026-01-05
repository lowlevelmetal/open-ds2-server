# Trace network activity via library functions
# Works better with Wine than syscall catchpoints

set pagination off
set confirm off

# Ignore Wine's internal signals
handle SIGUSR1 nostop noprint pass
handle SIGPWR nostop noprint pass
set print thread-events off

# Try breaking on ws2_32 functions (Windows sockets)
# These are what the game actually calls

# Break on send - will trigger during SSL handshake
break ws2_32!send
break ws2_32!recv
break ws2_32!connect

commands 1
  echo \n=== WS2_32 SEND ===\n
  bt 20
  continue
end

commands 2
  echo \n=== WS2_32 RECV ===\n
  bt 20
  continue
end

commands 3
  echo \n=== WS2_32 CONNECT ===\n
  bt 20
  continue
end

echo \nBreakpoints set on ws2_32 send/recv/connect\n
echo Connect to multiplayer now...\n
continue
