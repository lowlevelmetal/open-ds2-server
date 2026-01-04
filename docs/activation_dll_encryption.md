# Dead Space 2 activation.x86.dll Encryption Analysis

## Overview

The `activation.x86.dll` binary is protected using a custom encryption scheme based on XTEA. This document describes the encryption mechanism and the approach used to decrypt it.

## Binary Information

| Property | Value |
|----------|-------|
| Packed Size | 6,364,672 bytes |
| Unpacked Size | 6,791,168 bytes |
| Encryption | XTEA-based XOR stream cipher |
| Key | `[0x408EC6B5, 0xE2E4D222, 0x0614B34A, 0xF6BD5EC7]` |
| Delta | `0x9E3779B9` (standard XTEA constant) |

## Encrypted Sections

| Section | Raw Offset | VA Offset | Encrypted Size |
|---------|------------|-----------|----------------|
| .text   | 0x00000400 | 0x00001000 | 0x6F000 |
| .rdata  | 0x00070000 | 0x00071000 | 0x27000 |
| .data   | 0x00096400 | 0x00098000 | 0x02800 |
| .reloc  | 0x00098E00 | 0x000A0000 | 0x06400 |

**Non-encrypted sections:** .rsrc, S3, S4

## Encryption Algorithm

The encryption uses XTEA to generate a keystream, which is then XORed with the plaintext:

```
ciphertext = plaintext XOR keystream
```

### XTEA Implementation

The packer uses standard XTEA encryption with 32 rounds:

```c
void xtea_encrypt(uint32_t v[2], const uint32_t key[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0;
    uint32_t delta = 0x9E3779B9;
    
    for (int i = 0; i < 32; i++) {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum >> 11) & 3]);
    }
    
    v[0] = v0;
    v[1] = v1;
}
```

### Unpacker Stub Location

- **File offset:** 0xA1A49
- **Key initialization:** stub offset +048 to +058
- **XTEA loop:** stub offset +0E8 to +157
- **XOR application:** stub offset +157 to +17B
- **Block loop:** stub offset +0DA to +182

### Stub Variable Mapping

| Variable | Stack Location |
|----------|---------------|
| v0 | [ebp-48] |
| v1 | [ebp-44] |
| sum | [ebp-12] |
| round_counter | [ebp-20] |
| key[0..3] | [ebp-58] to [ebp-4C] |

## Known IVs (Back-computed)

Each section has its own initial IV value:

| Section | IV (v0, v1) |
|---------|-------------|
| .text   | (0x901BE361, 0xD588505C) |
| .rdata  | (0xB35E6200, 0x53C0B21E) |
| .data   | (0x18E164C6, 0x4B4A619E) |
| .reloc  | (0x901BE361, 0xD588505C) |

Note: .text and .reloc share the same IV.

## The Mystery: IV Progression

The encryption processes data in 8-byte blocks. For each block, a new IV is used. However, the IV progression between blocks does **NOT** follow any standard pattern:

### Tested Patterns (All Failed)

1. **OFB Mode (Output Feedback)**
   - Expected: IV[n+1] = XTEA(IV[n])
   - Result: Does not match

2. **CTR Mode (Counter)**
   - Tested: IV[n] = IV[0] + n (various interpretations)
   - Result: Does not match

3. **CFB Mode (Cipher Feedback)**
   - Expected: IV[n+1] = ciphertext[n]
   - Result: Does not match

4. **LFSR / xorshift64**
   - Tested multiple xorshift variants
   - Result: 0 matches

5. **LCG (Linear Congruential Generator)**
   - Tested MMIX, Java, glibc parameters
   - Result: 0 matches

### Block IV Analysis

First 8 blocks of .text section (back-computed IVs):

```
Block 0: IV = (0x901BE361, 0xD588505C)
Block 1: IV = (0x0ACA1EA2, 0x7357E5AE)
Block 2: IV = (0x64264E5E, 0xEC329D04)
Block 3: IV = (0xB92B1A15, 0x12E34B99)
Block 4: IV = (0x04E3AC10, 0xB20CD988)
Block 5: IV = (0xD16D28CA, 0x90F0F5D7)
Block 6: IV = (0xDB3B6DFE, 0x5C3F1A3F)
Block 7: IV = (0xFBDD8E87, 0xDD43EE79)
```

The XOR and subtraction between consecutive IVs shows no discernible pattern.

## Decryption Approach

Since the IV progression algorithm is unknown, we use **keystream extraction**:

1. Obtain a memory dump of the unpacked DLL at runtime
2. Extract keystream: `keystream = encrypted XOR decrypted`
3. Apply keystream: `decrypted = encrypted XOR keystream`

### How Keystream Extraction Works

The encryption is a simple XOR stream cipher:
```
ciphertext = plaintext XOR keystream
```

Therefore:
```
keystream = ciphertext XOR plaintext
plaintext = ciphertext XOR keystream
```

By obtaining a memory dump of the DLL after the runtime unpacker has decrypted it, we have both:
- **Ciphertext**: The encrypted sections in the packed DLL file
- **Plaintext**: The decrypted sections in the memory dump

XORing these together gives us the keystream that was used, which we can then apply to decrypt the original file.

### Tools

| Tool | Purpose |
|------|---------|
| [activation_decryptor.py](../tools/analysis/activation_decryptor.py) | Main decryption tool using keystream extraction |
| [xtea_decrypt.py](../tools/analysis/xtea_decrypt.py) | XTEA implementation for algorithm analysis |
| [decrypt_activation.py](../tools/analysis/decrypt_activation.py) | Additional analysis and keystream research |

### Step-by-Step Usage

#### Step 1: Create a Memory Dump

Using x64dbg, Process Hacker, or similar:

1. Start Dead Space 2 and wait for the main menu
2. The protection unpacks `activation.x86.dll` automatically
3. Attach a debugger or memory dumper to `deadspace2.exe`
4. Find the `activation.x86.dll` module (base address varies, typically ~0x79650000)
5. Dump the entire module memory to a file (e.g., `activation_dumped.bin`)

**Important**: The dump must be in VA (Virtual Address) layout, not file layout. The dump should be ~6.79 MB (unpacked size).

#### Step 2: Run the Decryptor

```bash
cd tools/analysis
python3 activation_decryptor.py <packed_dll> <memory_dump> [output_dll]

# Example:
python3 activation_decryptor.py \
    "/path/to/Dead Space 2/activation.x86.dll" \
    "activation_dumped.bin" \
    "activation_decrypted.dll"
```

#### Step 3: Verify Output

The decryptor will show:
```
Loading packed DLL: /path/to/activation.x86.dll
Loading memory dump: activation_dumped.bin
Packed size: 6,364,672 bytes
Dump size:   6,791,168 bytes

Processing sections:
------------------------------------------------------------
  .text   : decrypted 457,728 bytes ✓
  .rdata  : decrypted 156,672 bytes ✓
  .data   : decrypted 9,216 bytes ✓
  .rsrc   : not encrypted, skipping
  .reloc  : decrypted 35,840 bytes ✓

Verification:
------------------------------------------------------------
  .text   : ✓ MATCH
  .rdata  : ✓ MATCH
  .data   : ✓ MATCH
  .rsrc   : ✓ MATCH
  .reloc  : ✓ MATCH

✓ Decryption successful!
```

### Technical Details

The decryptor performs these operations:

1. **Parse PE Headers**: Reads section table to find encrypted regions
2. **Map Offsets**: Converts between file offsets (raw) and memory offsets (VA)
3. **Extract Keystream**: For each encrypted section:
   - Read encrypted bytes from packed file at `raw_ptr`
   - Read decrypted bytes from dump at `va` offset
   - Compute: `keystream[i] = packed[raw_ptr + i] XOR dump[va + i]`
4. **Apply Decryption**: Write decrypted bytes back to output file
5. **Verify**: Compare decrypted output with dump to ensure correctness

### Section Offset Mapping

| Section | File Offset (raw_ptr) | Memory Offset (VA) | Size |
|---------|----------------------|-------------------|------|
| .text   | 0x00000400 | 0x00001000 | 0x6F000 |
| .rdata  | 0x00070000 | 0x00071000 | 0x27000 |
| .data   | 0x00096400 | 0x00098000 | 0x02800 |
| .reloc  | 0x00098E00 | 0x000A0000 | 0x06400 |

## Verification

The .text section begins with a standard x86 function prologue after decryption:

```asm
55          push ebp
8B EC       mov ebp, esp
8B 45 0C    mov eax, [ebp+0Ch]
85 C0       test eax, eax
74 0F       jz short +0Fh
83 F8 02    cmp eax, 2
77 0A       ja short +0Ah
8B 4D 08    mov ecx, [ebp+08h]
...
```

This is the entry point of the first function in `.text`, confirming successful decryption.

## Limitations

- **Requires memory dump**: Cannot decrypt without a runtime dump
- **Dump must be VA layout**: File-layout dumps won't work
- **Version specific**: Different game versions may have different IVs

## Future Work

To create a standalone decryptor without memory dump:

1. **Deep reverse engineering** - Trace the unpacker's IV generation code in the S3/S4 sections
2. **Runtime debugging** - Set breakpoints in the XTEA loop to capture IV values for each block
3. **Pattern analysis** - Check if IVs might be derived from decrypted data (complex feedback mode)
4. **Brute force search** - For small sections, might be feasible to search for valid IV sequences

## Related Files

| File | Description |
|------|-------------|
| [tools/analysis/activation_decryptor.py](../tools/analysis/activation_decryptor.py) | Main decryption tool |
| [tools/analysis/xtea_decrypt.py](../tools/analysis/xtea_decrypt.py) | XTEA algorithm analysis |
| [tools/analysis/dll_analyzer.py](../tools/analysis/dll_analyzer.py) | Comprehensive PE analyzer |
| [tools/runtime_patcher/ds2_ssl_patcher_v11.c](../tools/runtime_patcher/ds2_ssl_patcher_v11.c) | SSL bypass patcher |
| [docs/ssl_verification_analysis.md](ssl_verification_analysis.md) | SSL callback analysis |
| [docs/activation_dll_reverse_engineering.md](activation_dll_reverse_engineering.md) | Full reverse engineering analysis |

## References

- XTEA Algorithm: https://en.wikipedia.org/wiki/XTEA
- TEA Family: https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
- PE File Format: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format
