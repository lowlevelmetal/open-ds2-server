# Dead Space 2 Runtime SSL Patcher

This tool patches the SSL certificate verification **in memory** at runtime, bypassing the DLL protection/packing that prevents static patching.

## Why Runtime Patching?

The `activation.x86.dll` in Dead Space 2 is protected with a packer/obfuscator. The SSL verification code is encrypted on disk and only decrypted when the game runs. This means:

1. Static file patching doesn't work reliably (the patcher was patching the wrong bytes)
2. We need to patch the code **after** it's been unpacked in memory

## How to Use

### On Windows (Native)

1. Start Dead Space 2 normally
2. **Before** going to multiplayer, run `ds2_ssl_patcher.exe` as Administrator
3. Wait for it to say "Successfully applied X patches"
4. Go to multiplayer in the game

### On Linux with Proton/Wine

1. Start Dead Space 2 through Steam
2. Open a terminal and run:
   ```bash
   # Find the game's Wine prefix
   cd ~/.steam/steam/steamapps/compatdata/47780/pfx
   
   # Run the patcher with Wine
   WINEPREFIX="$PWD" wine /path/to/ds2_ssl_patcher.exe
   ```
3. Wait for patches to apply
4. Go to multiplayer in the game

### Alternative: Steam Launch Options

You can also use Steam launch options to run the patcher automatically:

```
/path/to/ds2_ssl_patcher.exe & %command%
```

## Building from Source

### On Linux (Cross-compile)

```bash
i686-w64-mingw32-gcc -o ds2_ssl_patcher.exe ds2_ssl_patcher.c -lpsapi -static
```

### On Windows with MinGW

```bash
gcc -o ds2_ssl_patcher.exe ds2_ssl_patcher.c -lpsapi
```

### On Windows with MSVC

```bash
cl ds2_ssl_patcher.exe ds2_ssl_patcher.c /link psapi.lib
```

## How It Works

1. **Find Process**: Locates the running `deadspace2.exe` process
2. **Find Module**: Locates `activation.x86.dll` in the process memory
3. **Wait for Unpack**: Waits a few seconds for the DLL protection to unpack the code
4. **Scan for Patterns**: Searches for SSL verification patterns in the unpacked code
5. **Apply Patches**: Changes `SSL_VERIFY_PEER` (1) to `SSL_VERIFY_NONE` (0)

## Troubleshooting

### "Failed to open process"
- Run the patcher as Administrator
- Make sure the game is actually running

### "No patches were applied"
- The game might have a different version
- Try increasing `PATCH_DELAY_MS` in the source code (unpacking might take longer)
- The DLL structure may have changed

### Game still doesn't connect
- Make sure your `/etc/hosts` or `C:\Windows\System32\drivers\etc\hosts` has:
  ```
  127.0.0.1 gosredirector.ea.com
  ```
- Make sure the server is running on port 42127

## Technical Details

The patcher searches for this pattern in memory:
- `6A 01` (push 1) or `6A 02` (push 2) or `6A 03` (push 3)
- Followed by `E8 XX XX XX XX` (call) within ~20 bytes

This corresponds to code like:
```c
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, callback);
```

The patcher changes the push value from 1/2/3 to 0, which is `SSL_VERIFY_NONE`.
