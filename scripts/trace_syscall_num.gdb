# Catch actual syscalls by number
# connect = 42 on x86_64, socketcall = 102 on i386

set pagination off
set confirm off

# Ignore Wine signals
handle SIGUSR1 nostop noprint pass
handle SIGPWR nostop noprint pass
set print thread-events off

# Try both syscall numbers
catch syscall 42
catch syscall 102

commands 1
  echo \n=== SYSCALL 42 (connect x86_64) ===\n
  bt 30
  continue
end

commands 2
  echo \n=== SYSCALL 102 (socketcall i386) ===\n
  bt 30
  continue
end

echo \nCatching syscall 42 (connect) and 102 (socketcall)\n
echo Connect to multiplayer now...\n
continue
