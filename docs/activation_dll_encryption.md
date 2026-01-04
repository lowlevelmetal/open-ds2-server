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

### Tools

- **[activation_decryptor.py](../tools/analysis/activation_decryptor.py)** - Main decryption tool
- **[xtea_decrypt.py](../tools/analysis/xtea_decrypt.py)** - XTEA implementation for analysis

### Usage

```bash
# Create memory dump (using x64dbg or similar):
# 1. Load activation.x86.dll
# 2. Let unpacker run
# 3. Dump memory from image base

# Decrypt using keystream extraction:
python3 activation_decryptor.py activation.x86.dll activation_dumped.bin decrypted.dll
```

## Verification

The .text section begins with a standard x86 function prologue after decryption:

```
55          push ebp
8B EC       mov ebp, esp
8B 45 0C    mov eax, [ebp+0Ch]
85 C0       test eax, eax
74 0F       jz short +0Fh
...
```

## Future Work

To create a standalone decryptor without memory dump:

1. **Deep reverse engineering** - Trace the unpacker's IV generation code
2. **Runtime debugging** - Set breakpoints to capture IV values
3. **Pattern analysis** - Check if IVs might be derived from decrypted data (complex feedback)

## Related Files

- SSL patcher: [ds2_ssl_patcher_v11.exe](../ds2_ssl_patcher_v11.exe)
- Decrypted output: [activation_decrypted.dll](../tools/activation_decrypted.dll)

## References

- XTEA: https://en.wikipedia.org/wiki/XTEA
- TEA: https://en.wikipedia.org/wiki/Tiny_Encryption_Algorithm
