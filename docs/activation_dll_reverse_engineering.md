# Dead Space 2 activation.x86.dll Reverse Engineering

This document details the reverse engineering analysis of the `activation.x86.dll` DRM library
used by Dead Space 2 for online activation and multiplayer authentication.

## Overview

| Property | Value |
|----------|-------|
| **File Name** | activation.x86.dll |
| **Original Name** | drmlib.dll |
| **Packed Size** | 6,364,672 bytes |
| **Unpacked Size** | 6,791,168 bytes |
| **Image Base** | 0x10000000 |
| **Protection** | Tages Solidshield 2.0.3.0 (Themida-based) |
| **Compiler** | MSVC 10.0 (Visual Studio 2010) |
| **Libraries** | OpenSSL 1.0.0b (16 Nov 2010), libcurl-based HTTP |

## Binary Structure

### PE Sections

| Section | VA | Size | Flags | Description |
|---------|-----|------|-------|-------------|
| `.text` | 0x00001000 | 0x06FC00 (457KB) | RX | Code section (encrypted) |
| `.rdata` | 0x00071000 | 0x026400 (156KB) | R | Read-only data (encrypted) |
| `.data` | 0x00098000 | 0x002400 (9KB) | RW | Data section (encrypted) |
| `.rsrc` | 0x0009F000 | 0x000600 (1.5KB) | R | Resources (not encrypted) |
| `.reloc` | 0x000A0000 | 0x008C00 (35KB) | R | Relocations (encrypted) |
| S1 | 0x000A9000 | 0 | RW | Packer section (empty) |
| S2 | 0x000B9000 | 0 | RWX | Packer section (empty) |
| S3 | 0x00109000 | 0x56D400 (5.6MB) | RX | Packer code (virtualized) |
| S4 | 0x00677000 | 0x003000 (12KB) | R | Packer IAT |

### Encryption

The DLL uses XTEA-based XOR stream encryption on sections:
- **.text** - All executable code
- **.rdata** - String tables, OpenSSL structures
- **.data** - Global variables
- **.reloc** - Relocation table

**Decryption Key (XTEA):**
```
K[0] = 0x408EC6B5
K[1] = 0xE2E4D222
K[2] = 0x0614B34A
K[3] = 0xF6BD5EC7
```

The keystream generation uses a custom IV progression that doesn't match standard
modes (CTR, OFB, CFB). Decryption requires a memory dump of the unpacked binary.

## Exported Functions

| Ordinal | Name | RVA | Type | Description |
|---------|------|-----|------|-------------|
| 1 | `?Padding1@@YAKXZ` | 0x001610 | Stub | Returns 0xDEAD0001 |
| 2 | `?Padding2@@YAKXZ` | 0x0025B0 | Stub | Returns 0xDEAD0002 |
| 3 | `?Padding3@@YAKXZ` | 0x0025C0 | Stub | Returns 0xDEAD0003 |
| 4 | `?Padding4@@YAKXZ` | 0x002840 | Stub | Returns 0xDEAD0004 |
| 5 | `f2` | 0x0025D0 | VM Entry | Jumps to virtualized code |
| 6 | `start` | 0x001620 | VM Entry | Main entry point, jumps to VM |

The `Padding*` functions are placeholder stubs that return magic values (0xDEAD000X).
The actual functionality is in `start` and `f2`, which redirect to the virtualized
code in section S3 at address 0x101091F8.

## SSL/TLS Implementation

### OpenSSL Version
The DLL embeds **OpenSSL 1.0.0b** (16 Nov 2010), a statically linked build.

Key OpenSSL components:
- RSA encryption/signing
- X.509 certificate handling
- SHA-256, MD5 hashing
- EVP cipher interface
- BIO I/O abstraction

### SSL Verify Callbacks

Two potential SSL certificate verification callbacks were identified:

| Location | File Offset | RVA | VA | Purpose |
|----------|-------------|-----|-----|---------|
| Primary | 0x0052AC | 0x005EAC | 0x10005EAC | Main verify callback |
| Secondary | 0x063D94 | 0x064994 | 0x10064994 | Alternate callback |

The **primary callback at 0x0052AC** is the target for our SSL patcher. The function
signature pattern is:
```
55 8B EC 83 EC 20 A1 38 80 67 79
```

This translates to:
```asm
push    ebp
mov     ebp, esp
sub     esp, 0x20
mov     eax, ds:[79678038h]  ; Stack cookie
```

### Patching Strategy

To bypass SSL certificate verification, we patch the callback at runtime (after
Solidshield unpacks the code) to always return success:

**Patch Location:** File offset 0x52AC (RVA 0x5EAC)

**Original:**
```asm
55          push ebp
8B EC       mov ebp, esp
83 EC 20    sub esp, 0x20
...
```

**Patched:**
```asm
B8 01 00 00 00    mov eax, 1      ; Return 1 (success)
C3                ret              ; Return immediately
90 90 90 90       nop (padding)
```

## HTTP/Proxy Support

The DLL includes a libcurl-derived HTTP implementation with:

- HTTP/1.0 and HTTP/1.1 support
- HTTPS with SSL/TLS
- HTTP proxy tunneling (CONNECT method)
- Basic and Digest authentication
- Chunked transfer encoding

**Protocol Support:**
- HTTP/HTTPS
- FTP/FTPS (indicated but may not be used)
- SMTP, POP3, IMAP (indicated but may not be used)

## Imported DLLs

| DLL | Functions Used |
|-----|----------------|
| KERNEL32.dll | Memory, file, thread operations |
| USER32.dll | MessageBoxA (error dialogs) |
| SHELL32.dll | Shell operations |
| ole32.dll | COM support |
| OLEAUT32.dll | OLE automation |
| WS2_32.dll | Winsock networking |
| ADVAPI32.dll | Registry, crypto API |

## Runtime Behavior

### Initialization Flow

1. **DllMain** called on process attach
2. Solidshield unpacker extracts code from S3 to .text/.rdata/.data
3. Relocations applied
4. OpenSSL initialized (SSL_library_init equivalent)
5. Control passed to virtualized `start` function

### Network Communication

The DLL performs HTTPS requests to EA activation servers:
- Certificate verification via OpenSSL
- Authentication tokens exchanged
- License validation responses processed

**Known Server Endpoints (from deadspace2.exe):**
- `gosredirector.ea.com` - Game service redirector
- Blaze protocol servers (port 10041)

## Analysis Tools

### Decryptor
```bash
python3 tools/analysis/activation_decryptor.py \
    activation.x86.dll \
    activation_dumped.bin \
    decrypted.dll
```

### Analyzer
```bash
python3 tools/analysis/dll_analyzer.py decrypted.dll
```

### Runtime Patcher
```bash
# Build
i686-w64-mingw32-gcc -o ds2_ssl_patcher.exe \
    tools/runtime_patcher/ds2_ssl_patcher_v11.c -lpsapi

# Run
./ds2_ssl_patcher.exe
```

## Security Considerations

The Solidshield protection includes:
- **Code virtualization** - Critical code runs in VM interpreter
- **Import obfuscation** - Real IAT built at runtime
- **Anti-debug** - Various timing and debugger checks
- **Integrity checks** - Checksum validation of code sections

Our approach bypasses these by:
1. Letting the DLL unpack itself normally
2. Waiting for code to be decrypted in memory
3. Patching the SSL callback after unpacking completes

## Version Information

From the resource section:
- **Company:** Tages SAS
- **Product:** Solidshield Library
- **Version:** 2.0.3.0
- **Copyright:** Copyright (C) 2010 Tages SAS

## Related Files

| File | Description |
|------|-------------|
| `tools/analysis/activation_decryptor.py` | Keystream-based decryptor |
| `tools/analysis/dll_analyzer.py` | PE analysis tool |
| `tools/analysis/xtea_decrypt.py` | XTEA algorithm implementation |
| `tools/runtime_patcher/ds2_ssl_patcher_v11.c` | SSL bypass patcher |
| `docs/activation_dll_encryption.md` | Encryption documentation |

## Appendix: Function Statistics

- **Total function prologues:** ~302 functions identified
- **Code section size:** 457,728 bytes
- **Virtualized code:** 5,656,576 bytes (S3 section)

The majority of the DLL's logic is in the virtualized section, making static analysis
of the activation protocol difficult without running the code.
