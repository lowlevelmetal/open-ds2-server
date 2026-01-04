# Dead Space 2 activation.x86.dll Binary Protection Analysis

## Executive Summary

The `activation.x86.dll` file is protected with a custom encryption scheme. Through reverse engineering of the unpacker stub and comparison with a memory dump, we've successfully identified the encrypted sections and created a working decryptor.

**Status**: ✓ Decryption working via keystream extraction from memory dump

## File Structure

### Basic Information
- **Packed File Size**: 6,364,672 bytes
- **Unpacked Size**: 6,791,168 bytes (in memory)
- **Export Name**: drmlib.dll
- **6 exports** (DRM-related functions)

### PE Sections

| Section | Virtual Addr | Raw Offset | Raw Size | Status |
|---------|-------------|------------|----------|--------|
| .text   | 0x00001000  | 0x00000400 | 0x6FC00  | **ENCRYPTED** |
| .rdata  | 0x00071000  | 0x00070000 | 0x26400  | Unencrypted |
| .data   | 0x00098000  | 0x00096400 | 0x02400  | Unencrypted |
| .rsrc   | 0x0009F000  | 0x00098800 | 0x00600  | Unencrypted |
| .reloc  | 0x000A0000  | 0x00098E00 | 0x08C00  | **ENCRYPTED** |
| S1      | 0x000A9000  | 0x00000000 | 0x00000  | Empty (runtime) |
| S2      | 0x000B9000  | 0x00000000 | 0x00000  | Empty (runtime) |
| S3      | 0x00109000  | 0x000A1A00 | 0x56D400 | Contains unpacker |
| S4      | 0x00677000  | 0x0060EE00 | 0x03000  | Unencrypted |

### Entropy Analysis

| Section | Packed Entropy | Unpacked Entropy | Encrypted |
|---------|---------------|------------------|-----------|
| .text   | 8.000         | 6.640            | ✓ YES |
| .rdata  | 5.816         | 5.801            | ✓ YES |
| .data   | ~7.0          | ~6.0             | ✓ YES |
| .rsrc   | ~5.0          | ~5.0             | ✗ NO |
| .reloc  | 7.995         | 3.123            | ✓ YES |
| S3      | 8.000         | 6.144            | ✗ NO (unpacker code) |
| S4      | ~5.0          | ~5.0             | ✗ NO |

## Unpacker Analysis

### Entry Point Location
- **Entry RVA**: 0x00109049
- **File Offset**: 0xA1A49 (in S3 section)
- **Stub Size**: ~0x1AA bytes

### Entry Point Code Flow

```asm
+000: 9c              pushfd
+001: 50              push eax
+002: 51-57           push ecx/edx/ebx/esp/ebp/esi/edi
+009: 83 bc e4 2c...  cmp dword [esp+0x2C], 1
+010: 0f 85 8a 01..   jnz +0x18A (skip if already unpacked)
+017: e8 00 00 00 00  call next (get EIP)
+01C: 5e              pop esi
+01D: 81 ee 65 00..   sub esi, 0x65 (calculate base)
```

### XTEA Key Constants

Four 32-bit key values pushed onto stack:
```
push 0x0614B34A  ; Key part 4
push 0xF6BD5EC7  ; Key part 3
push 0x408EC6B5  ; Key part 2
push 0xE2E4D222  ; Key part 1
```

After stack frame setup, the key array in memory is:
```
k[0] = 0x408EC6B5
k[1] = 0xE2E4D222
k[2] = 0x0614B34A
k[3] = 0xF6BD5EC7
```

### XTEA Parameters

```
Delta: 0x9E3779B9 (standard TEA constant)
Rounds: 32 (standard)
Encrypted Size: 0x56D087 (5,689,479 bytes)
```

### Algorithm Structure

The unpacker stub contains inline XTEA code (not a function call):

1. **XTEA Round Loop** (+0xE8 to +0x155):
   - Uses standard XTEA encrypt operations
   - `shl v1, 4` at +0xF0
   - `shr v1, 5` at +0xF6
   - `shl v0, 4` at +0x127
   - `shr v0, 5` at +0x12D
   - `shr sum, 11` at +0x13A for key index

2. **XOR Operation** (+0x159 to +0x17B):
   - After 32 XTEA rounds, XORs result with encrypted data
   - `xor ecx, edx` at +0x161 (for v0)
   - `xor ecx, edx` at +0x174 (for v1)

3. **Block Loop** (+0x17F to +0x182):
   - Processes 8 bytes at a time
   - Continues until all encrypted data processed

### Algorithm Classification

The algorithm is **XTEA-based stream cipher** (XOR mode):
```
keystream = XTEA_ENCRYPT(counter_state)
plaintext = ciphertext XOR keystream
```

However, the counter state progression is **NOT standard CTR mode**:
- Consecutive keystream blocks don't show consistent counter increments
- The counter relationship between blocks is not +1 or any simple value

## Keystream Analysis

### .text Section Keystreams

| Block | Keystream V0 | Keystream V1 |
|-------|--------------|--------------|
| 0 | 0x40AB19F3 | 0x784C741F |
| 1 | 0x71E3A735 | 0x9EA06836 |
| 2 | 0x6A7DE12F | 0xD411557D |
| 3 | 0x0F87123C | 0x6A9D37C5 |
| 4 | 0xE78C8B76 | 0xCB01AF06 |
| 5 | 0x805911F5 | 0xA72D78A0 |
| 6 | 0x955A121E | 0xF9B70808 |
| 7 | 0xB8D74A04 | 0x75D40274 |

### Observations

1. **.text and .reloc share keystream block 0** - Both sections start with keystream `0x40AB19F3 0x784C741F`

2. **Counter reverse-engineering** - If we decrypt the keystream with XTEA, we get potential counter values:
   - Push key order: v0=0xA487E675, v1=0xB3AD744D
   - Stack key order: v0=0x733A9857, v1=0x07F66627
   - Derived key order: v0=0x901BE361, v1=0xD588505C

3. **Counter differences are not consistent** - Suggests either:
   - Custom counter progression algorithm
   - Possibly RC4-like state mixing
   - Or a different cipher altogether with XTEA as a component

## Decryption Challenges

### Algorithm Analysis

The encryption uses XTEA-based XOR stream cipher, but the keystream generation is **non-standard**:

1. **NOT CTR Mode**: Counter values between blocks don't follow any consistent increment pattern
2. **NOT OFB Mode**: XTEA(block[i]) ≠ block[i+1]
3. **Custom Algorithm**: The exact keystream generation remains unknown

### What We Discovered

1. **Keystream Reuse**: .text and .reloc sections start with nearly identical keystreams (first 23 bytes match exactly)
2. **Section Independence**: Each encrypted section appears to start from a similar keystream state
3. **XTEA Key**: Confirmed as `[0x408EC6B5, 0xE2E4D222, 0x0614B34A, 0xF6BD5EC7]`
4. **Initial Counter**: Appears to be (0, 0) but produces different output than expected

### Working Solution

Since the exact algorithm couldn't be determined, we use **keystream extraction**:
```
keystream = packed_section XOR unpacked_section (from memory dump)
```

This allows complete decryption of any packed binary if we have a memory dump.

## Practical Decryption

### Using the Decryptor Tool

```bash
# Decrypt using memory dump
python3 tools/analysis/activation_decryptor.py \
    /path/to/activation.x86.dll \
    /path/to/activation_dumped.bin \
    /path/to/output_decrypted.dll
```

### Obtaining a Memory Dump

The memory dump must be captured from a running game:

1. **Windows**: Use a tool like Process Hacker or x64dbg to dump the DLL from memory
2. **Wine/Proton**: Use wine debug tools or GDB attached to the process

The dump should:
- Be taken AFTER the DLL has unpacked itself
- Include the full DLL memory region (starting at its base address)
- Use VA-based layout (sections at their Virtual Address offsets)

## Files

| File | Description |
|------|-------------|
| `tools/activation_dumped.bin` | Memory dump of unpacked DLL (6.8 MB) |
| `tools/activation_decrypted.dll` | Decrypted DLL output |
| `tools/analysis/activation_decryptor.py` | Decryption tool using keystream extraction |
| `tools/analysis/xtea_decrypt.py` | Initial XTEA decryption attempt |
| `tools/analysis/decrypt_activation.py` | Analysis and comparison tool |
| `tools/analysis/keystream_text.bin` | Extracted .text section keystream |

## Decryption Results

```
Section   Status
--------  ------------------
.text     ✓ MATCH (457,728 bytes)
.rdata    ✓ MATCH (156,672 bytes)
.data     ✓ MATCH (9,216 bytes)
.rsrc     ✓ MATCH (not encrypted)
.reloc    ✓ MATCH (35,840 bytes)
S3        Expected mismatch (unpacker code)
S4        Expected mismatch (runtime data)
```

## SSL Verification Bypass

### SSL Verify Callback Location

The DLL uses OpenSSL 1.0.0b with `SSL_CTX_set_verify` to register a certificate verification callback. This callback rejects self-signed certificates.

| Address Type | Value |
|-------------|-------|
| File Offset | `0x52AC` |
| RVA | `0x5EAC` |
| VA (runtime) | `0x79655EAC` |

### Callback Function Analysis

```asm
; Function prologue at 0x52AC
+000: 55              push ebp
+001: 8B EC           mov ebp, esp
+003: 83 EC 20        sub esp, 0x20
+006: A1 38 80 67 79  mov eax, [__security_cookie]
...

; Error check at +0x25
+025: 3B FE           cmp edi, esi        ; Compare error code to 0
+027: 75 0E           jne error_path      ; Jump if error != 0

; Return 0 path at +0x30
+030: 33 C0           xor eax, eax        ; return 0
+032: E9 A1 01 00 00  jmp exit            ; jump to function exit
```

The callback:
1. Gets SSL error code via `X509_STORE_CTX_get_error`
2. If error == 0: processes certificate, returns 0 (unexpectedly)
3. If error != 0: checks whitelist of allowed errors, handles EA error codes 65000/65001

### Bypass Patch

**Pattern to search in memory:**
```
55 8B EC 83 EC 20 A1 38 80 67 79
```

**Patch (first 6 bytes):**
| | Original | Patched |
|---|---|---|
| Bytes | `55 8B EC 83 EC 20` | `B8 01 00 00 00 C3` |
| Assembly | `push ebp; mov ebp,esp; sub esp,0x20` | `mov eax,1; ret` |

This makes the callback immediately return 1 (accept any certificate).

### Runtime Patcher Usage

```bash
# Build the patcher (on Linux with mingw)
i686-w64-mingw32-gcc -o ds2_ssl_patcher.exe ds2_ssl_patcher.c -lpsapi

# Run with Wine/Proton before launching game
WINEPREFIX=... wine ds2_ssl_patcher.exe
```

## References

- XTEA: Extended Tiny Encryption Algorithm
- TEA Delta: 0x9E3779B9 = (√5 - 1) * 2³¹ (golden ratio)
- Standard XTEA: 32 rounds of Feistel network
- OpenSSL verify callback: Returns 1 = accept, 0 = reject
