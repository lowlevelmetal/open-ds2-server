#!/bin/bash
#
# Dead Space 2 Launcher with SSL Bypass Patcher
# For Linux/Proton
#

STEAM_APPID=47780
GAME_DIR="/mnt/games3/SteamLibrary/steamapps/common/Dead Space 2"
PROTON_DIR="/mnt/games3/SteamLibrary/steamapps/common/Proton 10.0"
COMPAT_DATA="/mnt/games3/SteamLibrary/steamapps/compatdata/$STEAM_APPID"
PATCHER_DIR="$(dirname "$(readlink -f "$0")")"

# Proton environment
export WINEPREFIX="$COMPAT_DATA/pfx"
export WINEFSYNC=1
export STEAM_COMPAT_CLIENT_INSTALL_PATH="$HOME/.steam/steam"
export STEAM_COMPAT_DATA_PATH="$COMPAT_DATA"

WINE="$PROTON_DIR/files/bin/wine"
PATCHER="$PATCHER_DIR/ds2_ssl_bypass_v6.exe"

echo "=== Dead Space 2 SSL Bypass Launcher ==="
echo ""

# Check if patcher exists
if [ ! -f "$PATCHER" ]; then
    echo "[-] Patcher not found at: $PATCHER"
    echo "    Building patcher..."
    cd "$PATCHER_DIR"
    i686-w64-mingw32-gcc -o ds2_ssl_bypass_v6.exe ds2_ssl_bypass_v6.c -lpsapi -Wall
    if [ $? -ne 0 ]; then
        echo "[-] Failed to build patcher"
        exit 1
    fi
    echo "[+] Patcher built successfully"
fi

# Check if game is already running
if pgrep -f "deadspace2.exe" > /dev/null 2>&1; then
    echo "[*] Dead Space 2 is already running"
    echo "[*] Running patcher..."
    "$WINE" "$PATCHER" 2>&1 | grep -v "^[0-9a-f]*:err:setupapi"
    exit $?
fi

echo "[*] Starting Dead Space 2 via Steam..."
echo "    (The game will launch, then the patcher will run)"
echo ""

# Launch the game via Steam (non-blocking)
steam steam://rungameid/$STEAM_APPID &
STEAM_PID=$!

echo "[*] Waiting for game to start and unpack DLL..."

# Wait for the game process to appear
MAX_WAIT=60
WAITED=0
while [ $WAITED -lt $MAX_WAIT ]; do
    if pgrep -f "deadspace2.exe" > /dev/null 2>&1; then
        echo "[+] Game process detected!"
        break
    fi
    sleep 1
    WAITED=$((WAITED + 1))
    if [ $((WAITED % 10)) -eq 0 ]; then
        echo "    Still waiting... ($WAITED seconds)"
    fi
done

if [ $WAITED -ge $MAX_WAIT ]; then
    echo "[-] Timeout waiting for game to start"
    exit 1
fi

# Wait additional time for DLL to unpack (Themida protection)
echo "[*] Waiting 10 seconds for DLL to unpack..."
sleep 10

# Run the patcher
echo "[*] Running SSL bypass patcher..."
"$WINE" "$PATCHER" 2>&1 | grep -v "^[0-9a-f]*:err:setupapi"

PATCH_RESULT=$?

if [ $PATCH_RESULT -eq 0 ]; then
    echo ""
    echo "[+] SUCCESS! Patches applied."
    echo "[*] You can now try to connect to multiplayer."
else
    echo ""
    echo "[-] Patching may have failed (exit code: $PATCH_RESULT)"
    echo "    Try running the patcher again manually:"
    echo "    $0"
fi

echo ""
echo "Press Enter to exit..."
read
