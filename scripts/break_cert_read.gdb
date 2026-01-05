# Break when the Equifax certificate string is accessed
# This will help us find the SSL verification code

set pagination off
set confirm off

# Hardware read watchpoint on the "Equifax" string
# This triggers when any code reads from this address
awatch *0x1f70390

echo Hardware watchpoint set on Equifax certificate string (0x1f70390)\n
echo When triggered, this will show which code accesses the certificate.\n
echo \n
echo Connect to multiplayer in the game now...\n
continue
