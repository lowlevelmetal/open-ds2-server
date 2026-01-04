# Dead Space 2 SSL Certificate Bypass

This tool patches the SSL certificate verification **in memory** at runtime, allowing the game to connect to custom servers with self-signed certificates.

## Files

| File | Description |
|------|-------------|
| `ds2_ssl_bypass.c` | **Recommended** - Clean rewrite with improved logging |
| `ds2_ssl_patcher_v11.c` | Legacy patcher (still works) |
| `launch_and_patch.sh` | Linux/Proton launch script with auto-patching |

## Why Runtime Patching?

The `activation.x86.dll` in Dead Space 2 is protected with a packer/obfuscator. The SSL verification code is encrypted on disk and only decrypted when the game runs. This means:

1. Static file patching doesn't work reliably (the patcher was patching the wrong bytes)
2. We need to patch the code **after** it's been unpacked in memory

## How to Use

### On Windows (Native)

1. Run `ds2_ssl_bypass.exe` as Administrator
2. Start Dead Space 2
3. Wait for "CERTIFICATE BYPASS ACTIVE" message
4. Go to multiplayer in the game

### On Linux with Proton/Wine

1. Start Dead Space 2 through Steam
2. Open a terminal and run:
   ```bash
   # Find the game's Wine prefix
   cd ~/.steam/steam/steamapps/compatdata/47780/pfx
   
   # Run the patcher with Wine
   WINEPREFIX="$PWD" wine /path/to/ds2_ssl_bypass.exe
   ```
3. Wait for patches to apply
4. Go to multiplayer in the game

### Alternative: Use launch_and_patch.sh

```bash
./launch_and_patch.sh
```

This script will:
1. Launch Dead Space 2 via Steam
2. Wait for the DLL to unpack
3. Apply the SSL patch automatically

## Building from Source

### On Linux (Cross-compile)

```bash
i686-w64-mingw32-gcc -o ds2_ssl_bypass.exe ds2_ssl_bypass.c -lpsapi -Wall -O2
```

### On Windows with MinGW

```bash
gcc -o ds2_ssl_bypass.exe ds2_ssl_bypass.c -lpsapi -Wall
```

### On Windows with MSVC

```bash
cl ds2_ssl_bypass.c /link psapi.lib
```

## How It Works

1. **Find Process**: Locates the running `deadspace2.exe` process
2. **Find Module**: Locates `activation.x86.dll` in the process memory
3. **Wait for Unpack**: Monitors the DLL until code patterns appear (indicates unpacking complete)
4. **Scan for Pattern**: Searches for the SSL verification callback function signature
5. **Apply Patch**: Changes the callback to `mov eax, 1; ret` (always accept certificates)

### Technical Details

The patcher finds the SSL verification callback at:
- **File offset**: 0x52AC (in decrypted DLL)
- **RVA**: 0x5EAC
- **Pattern**: `55 8B EC 83 EC 20 A1 38 80 67 79` (function prologue)

The patch changes:
```asm
; Original: Full callback function
push ebp
mov ebp, esp
sub esp, 0x20
...

; Patched: Always return 1 (accept)
mov eax, 1
ret
```

## Troubleshooting

### "Failed to open process"
- Run the patcher as Administrator
- Make sure the game is actually running

### "Pattern not found"
- Wait longer at the main menu before running the patcher
- The DLL may not have fully unpacked yet

### Game still doesn't connect
- Make sure your hosts file has:
  ```
  127.0.0.1 gosredirector.ea.com
  ```
- Make sure the server is running on port 42127
- Check the server logs for connection attempts
