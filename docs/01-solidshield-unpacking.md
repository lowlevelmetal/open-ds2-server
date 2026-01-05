# Complete Unpacking Documentation for activation.x86.dll

## Overview

**Game**: Dead Space 2 (PC, January 2011)  
**Publisher**: Electronic Arts / Visceral Games  
**DRM System**: **Solidshield** by Tagès SA  
**File**: `activation.x86.dll` - Activation/licensing component using OpenSSL  
**Internal Name**: `drmlib.dll`

This document describes the multi-layer packing scheme used by Solidshield protection and documents the complete unpacking process.

### Project Status: ✅ COMPLETE

All protection layers have been successfully bypassed:
- ✅ Layer 1 XTEA decryption - Fully reversed
- ✅ Layer 2 metamorphic obfuscation - Bypassed via memory dump
- ✅ Decrypted DLL extracted and reconstructed
- ✅ Static analysis completed

---

## Table of Contents

1. [DRM Identification](#drm-identification-solidshield)
2. [Layer 1: XTEA Encryption](#layer-1-xtea-stream-cipher)
3. [Layer 2: Metamorphic Obfuscation](#layer-2-metamorphic-obfuscation)
4. [Memory Dump Methodology](#memory-dump-methodology)
5. [Static Analysis Results](#static-analysis-results)
6. [Output Files](#output-files)
7. [Architecture Overview](#architecture-overview)

---

## DRM Identification: Solidshield

### What is Solidshield?

Solidshield is a DRM system developed by **Tagès SA** (the same company behind Tagès copy protection). It was commonly used by EA for PC game activation in the 2010-2012 era.

### Confirmed Characteristics (matching our analysis):

| Feature | Found in Binary | Solidshield Trait |
|---------|-----------------|-------------------|
| XTEA encryption | ✅ Layer 1 | Common in Tagès products |
| Binary wrapper | ✅ S3 section | TAGESCAP wrapper |
| Anti-debugging | ✅ 17,886 rdtsc | Standard protection |
| Hardware binding | ✅ MD5 hash in header | Activation fingerprint |
| Metamorphic obfuscation | ✅ 5.2MB obfuscated code | Anti-RE layer |
| 5-machine activation limit | Known issue | Server-side enforcement |

### User-Reported Issues (Reddit, Steam Forums)

- "Activation limit exceeded" errors common after hardware changes
- EA support often unable/unwilling to reset activations
- Still affects users trying to play in 2024/2025

---

## Layer 1: XTEA Stream Cipher [✅ FULLY ANALYZED]

### Entry Point Stub (0x10109049)

The DLL's entry point is located in the S3 section at RVA 0x109049. When DllMain is called with `DLL_PROCESS_ATTACH`:

```
10109049: pushfd                    ; Save flags
1010904A: push eax/ecx/edx/ebx/esp/ebp/esi/edi  ; Save registers
10109052: cmp dword ptr [esp+0x2c], 1  ; Check if reason == DLL_PROCESS_ATTACH
1010905A: jne 0x101091EA            ; Skip decryption if not
```

### Parameter Setup

The stub resolves and sets up parameters for XTEA decryption:

```
1010907C: push 0x56D087            ; Size to decrypt (5,689,479 bytes)
10109081: mov ecx, 0x1091F3        ; Start offset (S3 + 0x1F3)
         add ecx, edi              ; Calculate actual address
10109088: push ecx                 ; Buffer address
10109089: push 0                   ; Initialization parameter
1010908B: push 0                   ; Initialization parameter
1010908D: push 0x0614B34A          ; Key[3]
10109092: push 0xF6BD5EC7          ; Key[2]
10109097: push 0x408EC6B5          ; Key[1]
1010909C: push 0xE2E4D222          ; Key[0]
```

### XTEA Algorithm Details

The encryption uses a **stream cipher variant** of XTEA, not standard ECB or CTR mode:

```python
def xtea_stream_decrypt(data, key, rounds=32):
    delta = 0x9E3779B9
    result = bytearray()
    
    # State persists across blocks
    sum_val = 0
    v0, v1 = 0, 0
    
    for i in range(0, len(data), 8):
        # Generate keystream using encrypt direction
        kv0, kv1 = v0, v1
        s = sum_val
        for _ in range(rounds):
            kv0 = (kv0 + (((kv1 << 4 ^ kv1 >> 5) + kv1) ^ (s + key[s & 3]))) & 0xFFFFFFFF
            s = (s + delta) & 0xFFFFFFFF
            kv1 = (kv1 + (((kv0 << 4 ^ kv0 >> 5) + kv0) ^ (s + key[(s >> 11) & 3]))) & 0xFFFFFFFF
        
        # XOR ciphertext with keystream
        d0, d1 = struct.unpack('<II', data[i:i+8])
        result.extend(struct.pack('<II', d0 ^ kv0, d1 ^ kv1))
        
        # Update state for next block
        v0, v1 = kv0, kv1
        sum_val = s
    
    return bytes(result)
```

### Key Details

| Parameter | Value | Notes |
|-----------|-------|-------|
| key[0] | 0x408EC6B5 | From stack, reordered |
| key[1] | 0xE2E4D222 | From stack, reordered |
| key[2] | 0x0614B34A | From stack, reordered |
| key[3] | 0xF6BD5EC7 | From stack, reordered |
| delta | 0x9E3779B9 | Standard XTEA |
| rounds | 32 | Standard XTEA |

### S3 Section Header

```
Offset 0x00-0x28: Runtime addresses (VirtualProtect, LoadLibrary, etc.)
Offset 0x28-0x48: MD5 hash "81B398A3C645C1AE92218ED0C398B135" (purpose TBD)
Offset 0x49-0x1F2: XTEA decryption stub code
Offset 0x1F3-onwards: XTEA encrypted data (5,689,479 bytes)
```

---

## Layer 2: Metamorphic Obfuscation [🔄 PARTIALLY ANALYZED]

### Critical Finding: NOT a Virtual Machine!

**This is NOT a bytecode VM interpreter.** It is heavily **obfuscated native x86 code** using metamorphic/polymorphic techniques. This is characteristic of Solidshield's TAGESCAP protection layer.

### Structure

The decrypted Layer 1 data contains two parts:

1. **Obfuscated Unpacker** (0x00000 - 0x4FB35C): 5,223,261 bytes
2. **Encrypted Payload** (0x4FB35D - end): 466,215 bytes

### Why NOT a VM:

| Check | Result | VM Expectation |
|-------|--------|----------------|
| Indirect dispatch `jmp [reg]` | 0 found | Many (handler table) |
| Bytecode fetch `mov al,[esi]` | 12 found | Thousands |
| Handler table references | None | Required for VM |
| Spaghetti jumps `jmp rel32` | 105,352 | Few |

### Obfuscation Techniques

The unpacker employs extreme obfuscation:

| Technique | Count | Description |
|-----------|-------|-------------|
| JMP rel32 | 105,352 | Spaghetti code / control flow obfuscation |
| MOV operations | 261,012 | Data shuffling / junk insertion |
| PUSHFD/POPFD | 54,206/24,265 | Flag manipulation |
| AND EAX, 0x100 | 27,429 | Opaque predicates (trap flag checks) |
| RDTSC | 17,886 | Timing-based anti-debug |
| CPUID | 18,094 | Anti-VM / timing checks |
| PUSH SS/POP SS | 27,436 | Debug trap prevention |
| NOP | 13,030 | Junk insertion |

### Obfuscation Density

- **rdtsc density**: 3.4 per 1000 bytes
- **cpuid density**: 3.5 per 1000 bytes  
- **push ss/pop ss density**: 5.25 per 1000 bytes
- **jump density**: ~20 per 1000 bytes

This extreme density makes static analysis nearly impossible.

### Unpacker Entry Point

```asm
101091F3: push     0x4FB35D         ; VM code size
101091F8: push     0                ; Parameter
101091FA: pushfd                    ; Save flags
101091FB: push     0                ; Parameter
101091FD: push     ecx              ; Parameter
101091FE: mov      ecx, 0x6462      ; Loop counter (25,698)
```

### Anti-Debugging Techniques

The obfuscated unpacker uses multiple anti-debugging techniques:

1. **RDTSC Timing Checks** (17,886 instances): Measures execution time to detect debugger slowdown
2. **CPUID Checks** (18,094 instances): Detects VM/emulator environments
3. **Trap Flag Manipulation**: `PUSH SS/POP SS` sequence (27,436 pairs) prevents single-stepping
4. **Opaque Predicates**: `AND EAX, 0x100` (27,429 instances) - flag checks that always resolve the same way but confuse analysis
5. **Control Flow Obfuscation**: 105k+ jumps make breakpoint placement difficult
6. **INT 2D**: Anti-debug interrupt (6 instances)

### Unpacker Purpose

The obfuscated unpacker's purpose is to:
1. Decrypt the .text section (457,728 bytes)
2. Decrypt the .reloc section (35,840 bytes)
3. Transfer decrypted code to proper memory locations
4. Continue normal DLL execution

---

## Encrypted Payload Analysis

### Location & Size

- **Offset**: 0x4FB35D in decrypted Layer 1
- **Size**: 466,215 bytes
- **Entropy**: 7.9 (strongly encrypted)

### Size Relationship

| Data | Size |
|------|------|
| Encrypted payload | 466,215 bytes |
| .text section | 457,728 bytes |
| Difference | 8,487 bytes (~1.9% overhead) |

The payload is approximately .text size + small overhead, suggesting it contains the decrypted .text code.

### Encryption Algorithm (Unknown)

The payload encryption:
- Is NOT simple XTEA (no XTEA constants found in VM)
- Is NOT XOR with known keys
- Has no visible periodicity
- May use a custom cipher or standard cipher with hidden key

### Potential Algorithms (Based on VM Analysis)

1. **RC4-variant**: Found 256 constant, but context suggests flag check not RC4
2. **XOR with derived key**: Key may be computed from VM state
3. **Custom cipher**: The VM's complexity may hide a simple algorithm

---

## Original PE Section Status

| Section | RVA | Size | Status |
|---------|-----|------|--------|
| .text | 0x1000 | 457,728 | **ENCRYPTED** (entropy 7.96) |
| .rdata | 0x71000 | 156,672 | Clear - OpenSSL strings |
| .data | 0x98000 | 9,216 | Clear - C++ runtime |
| .reloc | 0xA0000 | 35,840 | **ENCRYPTED** (entropy 7.96) |
| S1 | 0xA9000 | 0 raw | Runtime buffer |
| S2 | 0xB9000 | 0 raw | Runtime buffer |
| S3 | 0x109000 | 5,690,368 | XTEA encrypted (Layer 1) |
| S4 | 0x677000 | 12,288 | Import table |

---

## Files Created

| File | Description |
|------|-------------|
| `scripts/xtea_layer1_decrypt.py` | Layer 1 XTEA decryption script |
| `decrypted_layer1.bin` | Decrypted VM + payload (5,689,476 bytes) |
| `REVERSE_ENGINEERING_NOTES.md` | Detailed analysis notes |
| `UNPACKING_DOCUMENTATION.md` | This document |

---

## Next Steps for Complete Unpacking

### Option 1: Dynamic Analysis (Recommended)

1. Load DLL in Windows debugger (x64dbg, OllyDbg)
2. Set hardware breakpoint on .text section writes
3. Let VM decrypt naturally
4. Dump decrypted sections

### Option 2: Emulation

1. Use Unicorn Engine with full PE emulation
2. Handle anti-debugging techniques:
   - Fake RDTSC responses
   - Ignore PUSH SS/POP SS traps
   - Provide VirtualProtect stub
3. Monitor memory writes to .text

### Option 3: Pattern Analysis

1. Trace VM execution to find decryption loop
2. Extract key from VM state
3. Implement standalone decryptor

### Option 4: Known Packer Tools

This protection has been identified as **Solidshield by Tagès SA**:

- **NOT Themida/WinLicense**: No Oreans markers found
- **NOT VMProtect**: No bytecode dispatch mechanism  
- **NOT Code Virtualizer**: No handler tables
- **IS Solidshield**: XTEA encryption, TAGESCAP binary wrapper, heavy anti-debug

Solidshield-specific unpackers may exist in the reverse engineering community.

---

## DLL Functionality (Based on Clear Sections)

From .rdata analysis, this DLL:

1. **Uses OpenSSL**: Crypto functions, X.509 certificates
2. **Uses libcurl**: Network operations, HTTP/HTTPS
3. **Activation purpose**: Name suggests license/activation checking
4. **C++ runtime**: Standard MSVC exception handling

### Notable Strings Found

```
- .\crypto\*.c (OpenSSL source paths)
- AES-128-CBC, AES-256-CBC
- sha256WithRSAEncryption
- CryptAcquireContextW, CryptGenRandom
- VirtualProtect, LoadLibraryA, GetProcAddress
- MessageBoxA (for error display)
```

---

## Conclusion

All protection layers have been successfully bypassed and the decrypted DLL is now available for analysis.

### Protection Summary

| Layer | Type | Status | Method |
|-------|------|--------|--------|
| Layer 1 | XTEA stream cipher | ✅ Reversed | Static analysis, custom decryptor |
| Layer 2 | Metamorphic x86 | ✅ Bypassed | Memory dump from running process |
| .text encryption | Unknown cipher | ✅ Bypassed | Runtime decryption by DRM itself |

### Protection Identified: Solidshield by Tagès SA

The packing scheme is **Solidshield**, a commercial DRM system by Tagès SA (also known for the Tagès copy protection system). Key identifiers:

- XTEA encryption (Layer 1) - common in Tagès products
- TAGESCAP-style binary wrapper with metamorphic obfuscation
- Extreme anti-debugging (rdtsc, cpuid, push ss/pop ss)
- Hardware-bound activation with 5-machine limit
- MD5 fingerprint in S3 header for activation binding

This DRM was commonly used by Electronic Arts for PC game activation during 2010-2012, and Dead Space 2 (January 2011) is a known Solidshield-protected title.

---

## Memory Dump Methodology

### Platform: Linux + Proton/Wine

The decrypted DLL was obtained by dumping memory from a running game instance under Proton.

### Wine Address Remapping Discovery

**Critical Finding**: Wine/Proton does NOT load the DLL at the PE header's ImageBase!

| Address Type | Expected | Actual |
|--------------|----------|--------|
| Image Base | 0x10000000 | 0x795E0000 |
| .text VA | 0x10001000 | 0x795E1000 |
| Entry Point | 0x10109049 | 0x796E9049 |

The address 0x10000000 exists in process memory but contains zeroed pages - Wine reserves it but loads the DLL elsewhere.

### Dump Process

1. **Start Game**: Launch Dead Space 2 via Steam/Proton
2. **Find PID**: `ps aux | grep -i dead` → Found PID 95664
3. **Locate DLL**: `cat /proc/<PID>/maps | grep activation`
4. **Verify MZ Header**: Read from actual base address
5. **Dump Sections**: Read all sections from memory
6. **Reconstruct PE**: Fix ImageBase, reassemble file

### Section Dump Results

| Section | Size | Entropy | Status |
|---------|------|---------|--------|
| .text | 458,752 | 3.25 | ✅ DECRYPTED |
| .rdata | 159,744 | 4.28 | ✅ DECRYPTED |
| .data | 28,672 | 3.97 | ✅ DECRYPTED |
| .rsrc | 4,096 | 2.28 | ✅ DECRYPTED |
| .reloc | 36,864 | 6.70 | ✅ DECRYPTED |
| S1 | 65,536 | 0.00 | ✅ Runtime buffer |
| S2 | 327,680 | 0.15 | ✅ Runtime buffer |
| S3 | 5,693,440 | 5.97 | ✅ Unpacker code |
| S4 | 12,288 | 6.05 | ✅ DECRYPTED |

**Total Dumped**: 6,787,072 bytes (6.47 MB)

---

## Static Analysis Results

### Tools Used

- **radare2** 5.9.8 - Disassembly and function analysis
- **objdump** (GNU Binutils 2.45.1) - PE header analysis
- **strings** - String extraction
- **Python** + pefile, capstone, lief - Custom analysis

### PE Structure

```
File: unpacked_activation_fixed.x86.dll
Architecture: i386
Format: pei-i386
Entry Point: 0x10109049 (in S3 unpacker section)
Image Base: 0x10000000
Characteristics: executable, 32-bit, DLL
DLL Characteristics: DYNAMIC_BASE, NX_COMPAT
```

### Function Analysis

**Total Functions Detected**: 13,202
- `.text` section: ~200 functions (actual DRM code)
- `S3` section: ~13,000 functions (obfuscated unpacker - no longer needed)

**Largest Functions in .text:**
| Address | Basic Blocks | Size | Purpose |
|---------|--------------|------|---------|
| 0x1000351f | 23 | 431 | Main activation flow |
| 0x10003a6e | 17 | 379 | Multi-branch validation |
| 0x10003376 | 26 | 320 | String operations |
| 0x10006510 | 33 | 305 | License validation |
| 0x10002846 | 6 | 277 | Stack cookie check |

### Export Functions

| Ordinal | Name | RVA | Purpose |
|---------|------|-----|---------|
| 1 | ?Padding1@@YAKXZ | 0x00001610 | Returns 0xDEAD0001 (debug stub) |
| 2 | ?Padding2@@YAKXZ | 0x000025B0 | Returns 0xDEAD0002 (debug stub) |
| 3 | ?Padding3@@YAKXZ | 0x000025C0 | Returns 0xDEAD0003 (debug stub) |
| 4 | ?Padding4@@YAKXZ | 0x00002840 | Returns 0xDEAD0004 (debug stub) |
| 5 | f2 | 0x000025D0 | Secondary entry |
| **6** | **start** | **0x00001620** | **Main entry - game calls this** |

### DllMain Analysis (0x10001000)

```asm
push    ebp
mov     ebp, esp
mov     eax, [ebp+0xC]      ; fdwReason
test    eax, eax
je      return_true
cmp     eax, 2              ; DLL_PROCESS_DETACH
ja      return_true
mov     eax, [ebp+8]        ; hinstDLL
push    eax
call    [init_function]     ; Internal initialization
return_true:
mov     eax, 1              ; TRUE
pop     ebp
ret     0xC
```

### Import Analysis

Imports are runtime-resolved. Referenced DLLs:

| DLL | Purpose |
|-----|---------|
| KERNEL32.dll | Core Windows API |
| USER32.dll | MessageBox for errors |
| SHELL32.dll | Shell operations |
| ole32.dll | COM/OLE |
| OLEAUT32.dll | OLE Automation |
| WS2_32.dll | Winsock networking |
| ADVAPI32.dll | Registry, crypto |
| NETAPI32.dll | Network statistics |

**Key APIs Used:**
- `CreateFileA/W`, `ReadFile`, `WriteFile` - File operations
- `CryptAcquireContextW`, `CryptGenRandom` - Windows crypto
- `GetVolumeInformationA` - Hardware fingerprinting
- `CreateProcessA` - Launch activation.exe helper
- `Process32First/Next` - Anti-debug process enumeration

### Embedded Libraries

**OpenSSL 1.0.0b (16 Nov 2010)**:
- AES-128/192/256-CBC/CFB/ECB/OFB
- DES-CBC
- RSA for signatures
- SHA-256, SHA-512, MD5
- X.509 certificate handling

**libcurl**:
- HTTP/HTTPS requests
- Proxy support
- POST for activation

### Critical Strings

**Activation Paths:**
```
%s\Solidshield\%s\activ.dat     ; License file location
activation.exe                   ; Helper executable
"%s" /activate                   ; Activation command
License is corrupted!            ; Error message
```

**Network Strings:**
```
Authentication failed: %d
The requested URL returned error: %d
Failed sending HTTP POST request
Content-Type: application/x-www-form-urlencoded
CONNECT %s:%hu HTTP/%s
```

---

## Output Files

### Primary Output

| File | Location | Description |
|------|----------|-------------|
| `unpacked_activation_fixed.x86.dll` | `dumps/` | Complete unpacked DLL (ImageBase fixed to 0x10000000) |
| `unpacked_activation.x86.dll` | `dumps/` | Raw dump (Wine ImageBase 0x795E0000) |
| `decrypted_text_section.bin` | `dumps/` | Raw .text section (458 KB) |

### Section Dumps

| File | Description |
|------|-------------|
| `section_text.bin` | Decrypted .text (458 KB) |
| `section_rdata.bin` | .rdata section (156 KB) |
| `section_data.bin` | .data section (28 KB) |
| `section_rsrc.bin` | Resources (4 KB) |
| `section_reloc.bin` | Relocations (36 KB) |
| `section_S1.bin` | Runtime buffer (64 KB) |
| `section_S2.bin` | Runtime buffer (320 KB) |
| `section_S3.bin` | Unpacker code (5.5 MB) |
| `section_S4.bin` | Import data (12 KB) |

### Intermediate Files

| File | Description |
|------|-------------|
| `decrypted_layer1.bin` | XTEA decrypted S3 data (5.69 MB) |

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                      activation.x86.dll                         │
│                      (Internal: drmlib.dll)                     │
├─────────────────────────────────────────────────────────────────┤
│  EXPORTS                                                        │
│  ├── start ──────────┐   (Game calls this)                      │
│  ├── f2 ─────────────┤   (Alternate entry)                      │
│  ├── Padding1-4      │   (Debug stubs: 0xDEAD000X)              │
│  └── DllMain         │   (Initialization)                       │
│                      ▼                                          │
│  ┌───────────────────────────────────────────────────────┐      │
│  │ S3 Section - Protection Layer (5.6 MB)                │      │
│  │                                                       │      │
│  │  ┌─────────────────────────────────────────────────┐  │      │
│  │  │ Layer 1: XTEA Stream Cipher                     │  │      │
│  │  │ - Key: [0x408ec6b5, 0xe2e4d222, ...]            │  │      │
│  │  │ - Decrypts 5.69 MB of Layer 2 code              │  │      │
│  │  └─────────────────────────────────────────────────┘  │      │
│  │                      ▼                                │      │
│  │  ┌─────────────────────────────────────────────────┐  │      │
│  │  │ Layer 2: Metamorphic Obfuscation                │  │      │
│  │  │ - 105k+ jumps (spaghetti code)                  │  │      │
│  │  │ - 18k rdtsc + 18k cpuid (anti-debug)            │  │      │
│  │  │ - 27k push ss/pop ss (trap flag tricks)         │  │      │
│  │  │ - Decrypts .text section at runtime             │  │      │
│  │  └─────────────────────────────────────────────────┘  │      │
│  └───────────────────────────────────────────────────────┘      │
│                      ▼                                          │
│  ┌───────────────────────────────────────────────────────┐      │
│  │ .text Section - Decrypted Application Code (458 KB)   │      │
│  │                                                       │      │
│  │  • OpenSSL 1.0.0b (AES, RSA, SHA-256, X.509)          │      │
│  │  • libcurl (HTTP/HTTPS activation)                    │      │
│  │  • License validation logic                           │      │
│  │  • Hardware fingerprinting                            │      │
│  │  • activ.dat file handling                            │      │
│  └───────────────────────────────────────────────────────┘      │
│                                                                 │
│  OTHER SECTIONS:                                                │
│  • .rdata: Strings, OpenSSL constants, crypto tables            │
│  • .data:  Runtime state variables                              │
│  • .rsrc:  Version info, manifest                               │
│  • .reloc: Base relocations                                     │
│  • S1/S2:  Runtime buffers (empty on disk)                      │
│  • S4:     Import address table                                 │
└─────────────────────────────────────────────────────────────────┘
```

### Activation Flow

```
Game Start
    │
    ▼
Load activation.x86.dll
    │
    ▼
DllMain(DLL_PROCESS_ATTACH)
    │
    ▼
Game calls start() export
    │
    ▼
┌───────────────────────────┐
│ S3 Protection Executes    │
│ • XTEA decrypt Layer 2    │
│ • Anti-debug checks       │
│ • Decrypt .text section   │
└───────────────────────────┘
    │
    ▼
┌───────────────────────────┐
│ Activation Logic          │
│ • Read activ.dat          │
│ • If missing/invalid:     │
│   - HTTP POST to EA       │
│   - Hardware fingerprint  │
│   - Write activ.dat       │
│ • Validate license        │
└───────────────────────────┘
    │
    ▼
Return to game (success/fail)
```

---

## Recommendations for Further Analysis

### Loading in Ghidra/IDA Pro

1. Open `dumps/unpacked_activation_fixed.x86.dll`
2. Focus on `.text` section (0x10001000-0x10070FFF)
3. **Ignore S3 section** - it's the obfuscator, not needed
4. Auto-analyze will find ~200 meaningful functions

### Key Functions to Examine

| Address | Description |
|---------|-------------|
| 0x10001000 | DllMain - initialization |
| 0x10001620 | start - main entry point |
| 0x1000351f | Main activation flow |
| 0x10006510 | License validation |
| 0x10003376 | String operations |

### Research Topics

1. **activ.dat Structure**:
   - RSA-signed license data
   - Hardware fingerprint hash
   - Activation timestamp
   - Machine counter

2. **Network Protocol**:
   - Activation server URLs
   - Request/response format
   - Certificate validation

3. **Hardware Fingerprinting**:
   - Volume serial numbers
   - Network adapter info
   - CPU/system identifiers

