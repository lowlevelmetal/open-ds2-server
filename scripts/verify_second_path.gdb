# verify_second_path.gdb - Check if second SSL path is used for multiplayer
#
# We found a second code path at 0x795f18e7 that also calls
# the handshake wrapper (0x795efe50). This might be the
# multiplayer SSL path.
#
# Usage: sudo gdb -x verify_second_path.gdb -p <PID>

set pagination off
set confirm off

echo \n=== Checking Second SSL Code Path ===\n\n

# Break at the call to handshake wrapper in SECOND path
echo Setting breakpoint at 0x795f18e7 (second SSL path)...\n
break *0x795f18e7
commands
    printf "\n>>> SECOND SSL PATH HIT! (0x795f18e7)\n"
    printf "    This is the multiplayer SSL path!\n"
    bt 5
    continue
end

# Also break at the error return
echo Setting breakpoint at 0x795f18f6 (error 0x2a in second path)...\n
break *0x795f18f6
commands
    printf "\n>>> ERROR in second path - setting 0x2a\n"
    bt 3
    continue  
end

# And the success path
echo Setting breakpoint at 0x795f18fd (success in second path)...\n
break *0x795f18fd
commands
    printf "\n>>> SUCCESS in second path!\n"
    continue
end

# Also set on the FIRST path for comparison
echo Setting breakpoint at 0x795eecf1 (first SSL path)...\n
break *0x795eecf1
commands
    printf "\n>>> FIRST SSL PATH HIT! (0x795eecf1)\n"
    bt 3
    continue
end

echo \nBreakpoints set. Connect to multiplayer now.\n
echo We'll see which path is taken.\n\n

continue
