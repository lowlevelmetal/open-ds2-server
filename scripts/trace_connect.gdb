# Trace multiplayer connection - ignore Wine signals
# Focus only on connect() to our target ports

set pagination off
set confirm off

# Ignore Wine's internal signals
handle SIGUSR1 nostop noprint pass
handle SIGPWR nostop noprint pass

# Don't stop on thread events
set print thread-events off

# Catch the connect syscall
catch syscall connect

commands
  # Print backtrace for each connect
  echo \n=== CONNECT SYSCALL ===\n
  bt 30
  echo \n
  continue
end

echo \nBreakpoint on connect() syscall set.\n
echo Wine signals will be ignored.\n
echo \n
echo Connect to multiplayer in the game now...\n
echo (Each connect() call will print a backtrace)\n
continue
