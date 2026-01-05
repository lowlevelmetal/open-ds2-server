# Watch for access to the Equifax certificate strings
# Run this and then try to connect to multiplayer

set pagination off
set confirm off

# Hardware read watchpoints on the certificate strings
# These will trigger when the code reads these addresses
rwatch *0x1f70390
rwatch *0x1f703b0

# Continue and wait for access
echo Watchpoints set on Equifax certificate strings\n
echo Try to connect to multiplayer now...\n
continue
