# Dead Space 2 Patching Tools

This directory contains utilities for patching Dead Space 2 to work with custom servers.

## Tools Overview

### 1. `ssl_pattern_finder.py` - Analysis Tool

Analyzes `activation.x86.dll` to find SSL certificate verification patterns that need to be patched.

```bash
python ssl_pattern_finder.py "/path/to/Dead Space 2/activation.x86.dll"
```

This tool will:
- Parse the PE structure of the DLL
- Find SSL-related strings
- Locate `SSL_CTX_set_verify` call patterns
- Identify potential verify callback functions
- Suggest patch locations

### 2. `ds2_patcher.py` - Automatic Patcher

Attempts to automatically patch the DLL by finding and modifying SSL verification patterns.

```bash
# Analyze only (no changes)
python ds2_patcher.py "/path/to/activation.x86.dll" --analyze

# Interactive mode (choose what to patch)
python ds2_patcher.py "/path/to/activation.x86.dll" --interactive

# Auto-patch (apply all found patches)
python ds2_patcher.py "/path/to/activation.x86.dll" --auto
```

### 3. `apply_patch.py` - Manual/Known Patches

Apply specific patches based on known offsets or patch files.

```bash
# Interactive mode (hex editor style)
python apply_patch.py "/path/to/activation.x86.dll" --interactive

# Apply from patch file
python apply_patch.py "/path/to/activation.x86.dll" --patch patches/steam_v1.json

# Apply single patch
python apply_patch.py "/path/to/activation.x86.dll" --offset 0x12345 --value 00

# Restore original from backup
python apply_patch.py "/path/to/activation.x86.dll" --restore
```

## Workflow

1. **First**, run the pattern finder to analyze your DLL:
   ```bash
   python ssl_pattern_finder.py "/path/to/activation.x86.dll" > analysis.txt
   ```

2. **Review** the suggested patches in the output

3. **Either** use the auto-patcher:
   ```bash
   python ds2_patcher.py "/path/to/activation.x86.dll" --auto
   ```
   
   **Or** apply specific patches manually:
   ```bash
   python apply_patch.py "/path/to/activation.x86.dll" --interactive
   ```

4. **Test** by launching the game and connecting to your server

5. **If it doesn't work**, restore and try different patches:
   ```bash
   python apply_patch.py "/path/to/activation.x86.dll" --restore
   ```

## Background

Dead Space 2 uses OpenSSL for SSL/TLS connections to EA's Blaze servers. The game validates server certificates against an embedded Root CA (Equifax Secure Certificate Authority).

To connect to custom servers with self-signed certificates, we need to patch the game to either:

1. **Disable certificate verification** - Change `SSL_CTX_set_verify` mode from `SSL_VERIFY_PEER` (1) to `SSL_VERIFY_NONE` (0)

2. **Modify the verify callback** - Make the callback function always return 1 (success)

3. **Replace the embedded CA** - (Advanced) Replace the Equifax CA with our own

## Technical Details

### SSL Verification in OpenSSL

```c
// Normal verification (what the game does)
SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);

// Disabled verification (what we want)
SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
```

### x86 Assembly Pattern

```asm
; Original: push 1 (SSL_VERIFY_PEER)
6A 01        push 1

; Patched: push 0 (SSL_VERIFY_NONE)  
6A 00        push 0
```

### Verify Callback

```c
// Original callback might look like:
int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    if (!preverify_ok) {
        return 0;  // Fail - certificate invalid
    }
    return preverify_ok;
}

// We want:
int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    return 1;  // Always succeed
}
```

## File Locations

### Steam (Windows)
```
C:\Program Files (x86)\Steam\steamapps\common\Dead Space 2\activation.x86.dll
```

### Steam (Linux/Proton)
```
~/.steam/steam/steamapps/common/Dead Space 2/activation.x86.dll
```

### Origin/EA App
```
C:\Program Files (x86)\Origin Games\Dead Space 2\activation.x86.dll
```

## Sharing Patches

If you find working patches for your version, please:

1. Note your file's MD5 hash (shown by the tools)
2. Document the patch offsets and bytes
3. Share via GitHub issue or PR

Example patch file format (JSON):
```json
{
  "metadata": {
    "game_version": "Steam",
    "file_hash": "abc123...",
    "tested": true
  },
  "patches": [
    {
      "offset": "0x12345",
      "original": "01",
      "patched": "00",
      "description": "SSL_VERIFY_PEER -> SSL_VERIFY_NONE"
    }
  ]
}
```

## Disclaimer

These tools are provided for educational and interoperability purposes. Only use them with games you legally own. Always keep backups of original files.
