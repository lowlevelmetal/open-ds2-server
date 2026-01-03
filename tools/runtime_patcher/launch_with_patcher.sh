#!/bin/bash
#
# Dead Space 2 SSL Patcher Launch Script for Linux/Proton
#
# This script:
# 1. Starts Dead Space 2 through Steam
# 2. Waits for the game to start
# 3. Runs the SSL patcher through the game's Wine prefix
#
# Usage: 
#   ./launch_with_patcher.sh
#
# Or set as Steam launch option:
#   /path/to/launch_with_patcher.sh %command%
#

# Configuration - adjust these paths as needed
STEAM_LIBRARY="/mnt/games3/SteamLibrary"
GAME_PATH="$STEAM_LIBRARY/steamapps/common/Dead Space 2"
COMPAT_DATA="$STEAM_LIBRARY/steamapps/compatdata/47780"
PATCHER_PATH="$GAME_PATH/ds2_ssl_patcher.exe"

# Find Proton
PROTON_PATH=$(find ~/.steam/root/steamapps/common -maxdepth 1 -name "Proton*" -type d | sort -V | tail -1)
if [ -z "$PROTON_PATH" ]; then
    PROTON_PATH=$(find /mnt -path "*/steamapps/common/Proton*" -maxdepth 5 -type d 2>/dev/null | sort -V | tail -1)
fi

echo "=== Dead Space 2 SSL Patcher ==="
echo "Game path: $GAME_PATH"
echo "Compat data: $COMPAT_DATA"
echo "Proton path: $PROTON_PATH"
echo ""

# Check if patcher exists
if [ ! -f "$PATCHER_PATH" ]; then
    echo "Error: Patcher not found at $PATCHER_PATH"
    exit 1
fi

# Function to run the patcher
run_patcher() {
    echo "[*] Waiting for game to initialize..."
    sleep 10  # Wait for game to start and DLLs to load
    
    echo "[*] Running SSL patcher..."
    
    # Set up Wine environment to match the game's prefix
    export WINEPREFIX="$COMPAT_DATA/pfx"
    export STEAM_COMPAT_DATA_PATH="$COMPAT_DATA"
    
    # Use Proton's Wine
    if [ -d "$PROTON_PATH" ]; then
        export WINE="$PROTON_PATH/files/bin/wine"
    else
        export WINE="wine"
    fi
    
    # Run the patcher
    cd "$GAME_PATH"
    "$WINE" "$PATCHER_PATH"
}

# If called with %command%, the game command is passed as arguments
if [ $# -gt 0 ]; then
    # Run patcher in background
    run_patcher &
    
    # Run the game
    exec "$@"
else
    # Just run the patcher (game should already be running)
    run_patcher
fi
