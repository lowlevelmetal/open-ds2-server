# Dead Space 2 activation.x86.dll Binary Analysis

## Overview

The `activation.x86.dll` file is a protected DLL that handles EA's online activation, Blaze protocol communication, and SSL/TLS connections for Dead Space 2. This document details the protection scheme and internal structure.

## File Information

| Property | Value |
|----------|-------|
| Filename | activation.x86.dll |
| File Size | 6,364,672 bytes (6.07 MB) |
| Unpacked Size | 6,791,168 bytes (6.48 MB) |
| Architecture | x86 (32-bit) |
| Image Base | 0x10000000 |
| Entry Point RVA | 0x00109049 |
| Export Name | drmlib.dll |

## PE Structure

### Sections

| # | Name | Virtual Addr | Virtual Size | Raw Size | Characteristics | Entropy |
|---|------|-------------|--------------|----------|-----------------|---------|
| 0 | .text | 0x00001000 | 0x00070000 | 0x0006FC00 | CODE, EXEC, READ | 8.00 |
| 1 | .rdata | 0x00071000 | 0x00027000 | 0x00026400 | DATA, READ | 5.82 |
| 2 | .data | 0x00098000 | 0x00007000 | 0x00002400 | DATA, READ, WRITE | 3.90 |
| 3 | .rsrc | 0x0009F000 | 0x00001000 | 0x00000600 | DATA, READ | 4.79 |
| 4 | .reloc | 0x000A0000 | 0x00009000 | 0x00008C00 | DATA, READ | 7.99 |
| 5 | S1 | 0x000A9000 | 0x00010000 | 0x00000000 | UDATA, READ, WRITE | N/A |
| 6 | S2 | 0x000B9000 | 0x00050000 | 0x00000000 | CODE, UDATA, EXEC, READ, WRITE | N/A |
| 7 | S3 | 0x00109000 | 0x0056E000 | 0x0056D400 | CODE, EXEC, READ | 8.00 |
| 8 | S4 | 0x00677000 | 0x00003000 | 0x00003000 | DATA, READ | 5.94 |

### Key Observations

1. **High Entropy Sections**: `.text`, `.reloc`, and `S3` all have entropy ~8.0, indicating encryption/compression
2. **Uninitialized Sections**: `S1` and `S2` have zero raw size - allocated at runtime
3. **S2 Permissions**: Has EXEC+WRITE, typical for unpacker workspace
4. **S3 Section**: Main packed payload (5.7 MB)

## Protection Scheme

### Encryption Algorithm: XTEA

The binary uses **XTEA (Extended Tiny Encryption Algorithm)** for code protection.

#### Algorithm Parameters

| Parameter | Value |
|-----------|-------|
| Delta Constant | 0x9E3779B9 |
| Block Size | 64 bits (8 bytes) |
| Rounds | 32 |
| Key Size | 128 bits (4 × 32-bit words) |

#### Encryption Key

```
K[0] = 0x0614B34A
K[1] = 0xF6BD5EC7
K[2] = 0x408EC6B5
K[3] = 0xE2E4D222
```

### Entry Point Analysis

The entry point at RVA `0x00109049` contains the unpacker stub:

```asm
; Prologue - Save all registers
00109049:  pushfd
0010904A:  push eax
0010904B:  push ecx
0010904C:  push edx
0010904D:  push ebx
0010904E:  push esp
0010904F:  push ebp
00109050:  push esi
00109051:  push edi

; Check for DLL_PROCESS_ATTACH
00109052:  cmp dword [esp+0x2c], 1
0010905A:  jne skip_unpack

; Position-independent code setup
00109060:  call $+5           ; Push EIP onto stack
00109065:  pop esi            ; ESI = current address
00109066:  sub esi, 0x65      ; Calculate base of S3 section
0010906C:  mov edi, esi
0010906E:  sub edi, 0x109000  ; Calculate image base delta

; Push XTEA key constants
0010908D:  push 0x0614B34A
00109092:  push 0xF6BD5EC7
00109097:  push 0x408EC6B5
0010909C:  push 0xE2E4D222

; Setup stack frame for decryption
001090A4:  mov ebp, esp
001090A6:  sub esp, 0x40
```

### XTEA Decryption Loop

Located at approximately RVA `0x001090FC`:

```asm
; Initialize delta
mov dword [ebp-0x10], 0x9E3779B9

; For each 64-bit block
outer_loop:
    ; 32 rounds of XTEA
    inner_loop:
        ; v0 += ((v1<<4 ^ v1>>5) + v1) ^ (sum + key[sum & 3])
        mov ecx, [ebp-0x2c]      ; v1
        shl ecx, 4               ; v1 << 4
        mov edx, [ebp-0x2c]      
        shr edx, 5               ; v1 >> 5
        xor ecx, edx             ; (v1<<4) ^ (v1>>5)
        mov edx, [ebp-0x2c]
        add ecx, edx             ; + v1
        mov edx, [ebp-0x0c]      ; sum
        and edx, 3               ; sum & 3
        mov ebx, [ebp+edx*4-0x28] ; key[sum & 3]
        add ebx, [ebp-0x0c]      ; + sum
        xor ecx, ebx
        add [ebp-0x30], ecx      ; v0 += result
        
        ; Similar for v1...
```

## Unpacking Process

1. **DllMain Entry**: Triggered on `DLL_PROCESS_ATTACH`
2. **Base Calculation**: Uses `call $+5; pop reg` technique
3. **Memory Preparation**: Allocates `S1` and `S2` sections
4. **Decryption**: XTEA decrypts `S3` section in place
5. **Decompression**: Unpacks to original `.text`, `.rdata` sections
6. **Relocation**: Applies relocations from `.reloc` table
7. **Import Resolution**: Rebuilds IAT
8. **Transfer Control**: Jumps to original entry point

## Exported Functions

```
drmlib.dll exports:
  [0] ?Padding1@@YAKXZ
  [1] ?Padding2@@YAKXZ
  [2] ?Padding3@@YAKXZ
  [3] ?Padding4@@YAKXZ
  [4] f2
  [5] start
```

## Import Table (Packed State)

Only minimal imports visible in packed state:
- KERNEL32.dll
- USER32.dll
- SHELL32.dll
- ole32.dll
- OLEAUT32.dll
- WS2_32.dll
- ADVAPI32.dll

## Anti-Analysis Techniques

1. **Encryption**: Maximum entropy (8.0) in code sections
2. **No Signatures**: No Themida/VMProtect strings detected
3. **Stripped Timestamps**: All timestamps set to 0
4. **Minimal Imports**: Real imports resolved at runtime
5. **Position-Independent**: All addresses calculated dynamically

## Memory Layout After Unpacking

When the DLL is loaded and unpacked in memory (base 0x795E0000 in our dump):

| Address | Size | Content |
|---------|------|---------|
| 0x795E0000 | 0x1000 | PE Headers |
| 0x795E1000 | 0x70000 | .text (decrypted code) |
| 0x795F1000 | 0x27000 | .rdata (decrypted data) |
| 0x79618000 | 0x7000 | .data |
| 0x7961F000 | 0x1000 | .rsrc |
| 0x79620000 | 0x9000 | .reloc |
| 0x79629000 | 0x10000 | S1 (runtime data) |
| 0x79639000 | 0x50000 | S2 (runtime code) |
| 0x79689000 | 0x56E000 | S3 (original packed, now decrypted) |
| 0x79FF7000 | 0x3000 | S4 |

## SSL/TLS Implementation

The unpacked DLL contains a full OpenSSL implementation with:
- SSLv3 and TLS 1.0 support
- Custom X.509 certificate verification callback
- RC4-SHA and RC4-MD5 cipher preferences

### X.509 Verification Callback

Located at RVA `0x5AC5` in the unpacked code (address 0x795E5AC5 with base 0x795E0000).

See [ssl_verification_analysis.md](ssl_verification_analysis.md) for detailed callback analysis.

## References

- [XTEA Algorithm](https://en.wikipedia.org/wiki/XTEA)
- [PE Format Specification](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
