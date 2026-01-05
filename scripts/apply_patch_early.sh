#!/bin/bash
# SSL Certificate Verification Bypass for Dead Space 2
# This script waits for the game to start and applies the patch immediately

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKIP_VERIFY_SCRIPT="$SCRIPT_DIR/skip_ssl_verify.gdb"

echo "=== Dead Space 2 SSL Patch Applier ==="
echo ""
echo "Instructions:"
echo "1. Run this script in a terminal"
echo "2. Start Dead Space 2 from Steam"
echo "3. Wait for patch confirmation"
echo "4. Then attempt multiplayer connection"
echo ""

echo "Waiting for Dead Space 2 to start..."
while ! pgrep -f "deadspace2.exe" > /dev/null 2>&1; do
    sleep 0.5
done

echo "Dead Space 2 processes found, waiting for activation.dll to load..."

# Wait for activation.dll to load (may take a few seconds)
PID=""
for i in {1..30}; do
    for pid in $(pgrep -f "deadspace2.exe"); do
        if grep -q "activation.x86.dll" /proc/$pid/maps 2>/dev/null; then
            PID=$pid
            break 2
        fi
    done
    sleep 0.5
done

if [ -z "$PID" ]; then
    echo "⚠ Error: Could not find process with activation.dll loaded after 15 seconds"
    exit 1
fi

echo "✓ Found Dead Space 2 with activation.dll loaded (PID: $PID)"

echo ""
echo "Applying SSL verification bypass patch..."
echo "  Patch: Skip SSL_set_verify call (je -> jmp at 0x795eecec)"

# Apply the skip patch (single byte: 0x74 -> 0xeb)
sudo gdb -q -batch -x "$SKIP_VERIFY_SCRIPT" -p $PID 2>&1 | grep -E "^(===|Changing|Patch|After|jmp)"

if [ $? -eq 0 ]; then
    echo ""
    echo "=== Patch Applied Successfully! ==="
    echo ""
    echo "You can now attempt to connect to multiplayer."
    echo "The game will accept any SSL certificate."
else
    echo ""
    echo "=== Patch Failed ==="
    echo "Check if the game is still running and try again."
fi
