# Dead Space 2 Client Patching Guide

## The Problem

Dead Space 2's `activation.x86.dll` validates the SSL certificate against EA's embedded root CA (Equifax Secure Certificate Authority). Since our server uses a self-signed certificate, the game rejects the connection.

## Solutions

### Option 1: Use Our Patching Tools (Recommended)

We provide Python tools to analyze and patch `activation.x86.dll`. These are located in the `tools/` directory.

**DLL Location**: `<Steam>/steamapps/common/Dead Space 2/activation.x86.dll`

#### Quick Start

```bash
# Navigate to the tools directory
cd tools/

# Step 1: Analyze the DLL to find patch locations
python ssl_pattern_finder.py "/path/to/Dead Space 2/activation.x86.dll"

# Step 2: Auto-patch (creates backup automatically)
python ds2_patcher.py "/path/to/Dead Space 2/activation.x86.dll" --auto

# Or use interactive mode for more control
python apply_patch.py "/path/to/Dead Space 2/activation.x86.dll" --interactive
```

See [tools/README.md](../tools/README.md) for detailed documentation.

### Option 2: Manual Hex Patching

If the automated tools don't work for your version, you can patch manually.

#### What to Patch

We need to find the SSL certificate verification call and make it always succeed:

1. **Find `SSL_CTX_set_verify`** call and change the verify mode to `SSL_VERIFY_NONE` (0)
2. **Find the verify callback** and make it always return 1 (success)

#### Steps

1. **Backup the original file**:
   ```bash
   cp activation.x86.dll activation.x86.dll.backup
   ```

2. **Find the verification code** using a disassembler (Ghidra, IDA, x64dbg):
   - Search for string references to certificate errors
   - Look for calls to OpenSSL verification functions
   - Find the callback that returns the verification result

3. **Common patch patterns**:
   
   **Pattern A - Force SSL_VERIFY_NONE**:
   Look for: `6A 01` or `6A 02` (push 1 or push 2) before `call SSL_CTX_set_verify`
   Change to: `6A 00` (push 0 = SSL_VERIFY_NONE)
   
   **Pattern B - Force verify callback to succeed**:
   Find the verify callback function (called during handshake)
   Change the return to always be 1:
   ```asm
   ; Replace the function body with:
   B8 01 00 00 00    ; mov eax, 1
   C3                ; ret
   ```

### Option 3: Use a DLL Proxy

Create a proxy DLL that intercepts SSL functions:

1. Create `dinput8.dll` or `version.dll` proxy
2. Hook `SSL_CTX_set_verify` to always use `SSL_VERIFY_NONE`
3. Place in game directory

## Using Ghidra to Find Patch Locations

1. Load `activation.x86.dll` in Ghidra
2. Search for string: "certificate verify failed"
3. Find XREF to that string
4. The calling function is likely the verify callback
5. Patch that function to return 1

### Using x64dbg (Runtime)

1. Load Dead Space 2 in x64dbg
2. Set breakpoint on `SSL_CTX_set_verify` (in activation.x86.dll)
3. When hit, check the verify_mode parameter
4. Patch it to 0 (SSL_VERIFY_NONE)

## Using the Analysis Tools

Our `tools/ssl_pattern_finder.py` provides much more detailed analysis than a simple script.

Example output:
```
[+] Image base: 0x10000000
[+] Number of sections: 5
    Section: .text    VA: 0x00001000 Size:   245760 [CODE]
    Section: .rdata   VA: 0x0003D000 Size:    81920
    ...

[*] Searching for SSL-related strings...
    Found: SSL_CTX_set_verify at 2 location(s)
    Found: certificate verify failed at 1 location(s)

[*] Searching for SSL_CTX_set_verify call patterns...
    Found 47 potential patterns

    Offset: 0x0001A234 (RVA: 0x0001B234)
    Section: .text
    Verify mode: 1 (SSL_VERIFY_PEER)
    Context: 6a016a00e8...
```

The tool identifies the most likely patch locations by analyzing:
- String references to SSL error messages
- Code patterns that match `SSL_CTX_set_verify` calling convention
- Functions that return 0 (potential verify failure callbacks)

## Verification

After patching, the game should:
1. Connect to the redirector on port 42127
2. Complete the SSL handshake (you'll see it in server logs)
3. Send a Blaze `ServerInstanceRequest` packet

## Safety Notes

- **Always backup original files** before patching
- Patched games may trigger antivirus warnings
- This patch is for connecting to custom servers only
- The patch disables SSL certificate validation which is insecure for real internet use

## Community Resources

Check these projects for similar patches:
- ME3 Server emulators (same Blaze protocol)
- Battlefield server emulators
- Other EA game revival projects

## Reporting Success

If you successfully patch the game, please share:
1. The exact byte offset in activation.x86.dll
2. The original bytes
3. The patched bytes
4. Your game version (Steam, Origin, etc.)

This will help others get their games working!
