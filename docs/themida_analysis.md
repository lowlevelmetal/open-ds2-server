# Themida/WinLicense Unpacker Analysis for activation.x86.dll

## PE Header Summary

- **File Size:** 6,364,672 bytes
- **Image Base:** 0x10000000
- **Entry Point RVA:** 0x109049 (in section S3)
- **Entry Point VA:** 0x10109049
- **Sections:** 9

### Section Layout

| # | Name   | Virtual Addr | Virtual Size | Raw Offset | Raw Size   | Flags |
|---|--------|--------------|--------------|------------|------------|-------|
| 0 | .text  | 0x00001000   | 0x00070000   | 0x00000400 | 0x0006FC00 | CODE,EXEC,READ |
| 1 | .rdata | 0x00071000   | 0x00027000   | 0x00070000 | 0x00026400 | DATA,READ |
| 2 | .data  | 0x00098000   | 0x00007000   | 0x00096400 | 0x00002400 | DATA,READ,WRITE |
| 3 | .rsrc  | 0x0009F000   | 0x00001000   | 0x00098800 | 0x00000600 | DATA,READ |
| 4 | .reloc | 0x000A0000   | 0x00009000   | 0x00098E00 | 0x00008C00 | DATA,READ |
| 5 | S1     | 0x000A9000   | 0x00010000   | 0x00000000 | 0x00000000 | UNINIT,READ,WRITE |
| 6 | S2     | 0x000B9000   | 0x00050000   | 0x00000000 | 0x00000000 | CODE,UNINIT,EXEC,READ,WRITE |
| 7 | **S3** | 0x00109000   | 0x0056E000   | 0x000A1A00 | 0x0056D400 | CODE,EXEC,READ |
| 8 | S4     | 0x00677000   | 0x00003000   | 0x0060EE00 | 0x00003000 | DATA,READ |

- **S3** is the Themida-packed section containing the packer code
- **S1, S2** are uninitialized sections used during unpacking
- Original code is in **.text** but encrypted/compressed

---

## Entry Point Analysis (0x10109049)

### Phase 1: DllMain Check & Register Save

\`\`\`asm
10109049  pushf                  ; Save flags
1010904A  push eax               ; Save all registers (PUSHAD pattern)
1010904B  push ecx
1010904C  push edx
1010904D  push ebx
1010904E  push esp
1010904F  push ebp
10109050  push esi
10109051  push edi
10109052  cmp dword [esp+0x2c],0x1  ; Check DllMain fdwReason
1010905A  jnz 0x101091ea            ; If not DLL_PROCESS_ATTACH, skip to exit
\`\`\`

The code checks if this is DLL_PROCESS_ATTACH (reason=1). The value at [esp+0x2c] is the fdwReason parameter.

### Phase 2: Position-Independent Code (PIC) Setup

\`\`\`asm
10109060  call 0x10109065        ; call $+5 trick (get EIP)
10109065  pop esi                ; ESI = current EIP (0x10109065)
10109066  sub esi,0x65           ; ESI = 0x10109000 (section S3 base)
1010906C  mov edi,esi            ; EDI = S3 base
1010906E  sub edi,0x109000       ; EDI = image delta (0 if loaded at preferred base)
                                 ; EDI = actual_base - 0x10000000
\`\`\`

This is classic position-independent code. The "call $+5; pop" trick gets the current instruction pointer, then calculates the image base delta for relocation.

### Phase 3: Load Decryption Parameters

\`\`\`asm
10109074  mov ecx,esi            ; ECX = section base
10109076  mov ecx,[ecx]          ; ECX = dword at section start
10109078  add ecx,edi            ; Apply relocation delta
1010907A  push dword [ecx]       ; Push function pointer (VirtualProtect?)
1010907C  push dword 0x56d087    ; Push size: 5,689,479 bytes
10109081  mov ecx,0x1091f3       ; 
10109086  add ecx,edi            ; Apply delta
10109088  push ecx               ; Push address to decrypt
\`\`\`

### Phase 4: Push Decryption Key (XTEA Key)

\`\`\`asm
10109089  push 0x0               ; Reserved
1010908B  push 0x0               ; Reserved  
1010908D  push 0x614b34a         ; Key[3]
10109092  push 0xf6bd5ec7        ; Key[2]
10109097  push 0x408ec6b5        ; Key[1]
1010909C  push 0xe2e4d222        ; Key[0]
101090A1  push 0x0               ; Reserved
\`\`\`

This pushes a 128-bit key for XTEA decryption:
- **Key:** \`E2E4D222 408EC6B5 F6BD5EC7 0614B34A\`

### Phase 5: XTEA Decryption Loop

The code from 0x101090A3 onwards implements **XTEA (eXtended Tiny Encryption Algorithm)** decryption:

\`\`\`asm
101090A3  push ebp
101090A4  mov ebp,esp
101090A6  sub esp,0x40           ; Allocate 64 bytes local vars

; ... setup ...

10109103  mov dword [ebp-0x10],0x9e3779b9  ; XTEA delta constant!
\`\`\`

The magic constant **0x9E3779B9** is the XTEA/TEA delta (derived from golden ratio).

### XTEA Core Algorithm (Decryption Round)

\`\`\`asm
; Inner loop (32 rounds per block)
10109133  inc dword [ebp-0x14]       ; round_counter++
10109136  mov ecx,[ebp-0x2c]         ; v1
10109139  shl ecx,4                  ; v1 << 4
1010913C  mov edx,[ebp-0x2c]         ; v1
1010913F  shr edx,5                  ; v1 >> 5
10109142  xor ecx,edx                ; (v1 << 4) ^ (v1 >> 5)
10109144  mov edx,[ebp-0x2c]
10109147  add ecx,edx                ; + v1
10109149  mov edx,[ebp-0xc]          ; sum
1010914C  and edx,0x3                ; sum & 3
1010914F  mov ebx,[ebp+edx*4-0x28]   ; key[sum & 3]
10109153  mov edx,[ebp-0xc]
10109156  add ebx,edx                ; key[sum&3] + sum
10109158  xor ecx,ebx                ; XOR with key component
1010915A  mov edx,[ebp-0x30]         ; v0
1010915D  add ecx,edx                ; v0 += result
1010915F  mov [ebp-0x30],ecx         ; store v0

10109162  mov ecx,[ebp-0xc]          ; sum
10109165  mov edx,[ebp-0x10]         ; delta (0x9e3779b9)
10109168  add ecx,edx                ; sum += delta
1010916A  mov [ebp-0xc],ecx          ; store sum

; Second half of round (similar for v1)
1010916D  mov ecx,[ebp-0x30]         ; v0
10109170  shl ecx,4
10109173  mov edx,[ebp-0x30]
10109176  shr edx,5
10109179  xor ecx,edx
; ... continues ...

1010919C  cmp dword [ebp-0x14],0x20  ; 32 rounds?
101091A0  jl 0x10109133              ; Loop if not done
\`\`\`

### Phase 6: Write Decrypted Data

\`\`\`asm
101091A2  mov edx,[ebp-0x18]     ; output pointer
101091A5  mov ecx,[edx]          ; load encrypted dword
101091A7  mov edx,[ebp-0x30]     ; v0 result
101091AA  xor ecx,edx            ; decrypt
101091AC  mov edx,[ebp-0x18]
101091AF  mov [edx],ecx          ; store decrypted
101091B1  add dword [ebp-0x18],0x4  ; advance pointer

101091B5  mov edx,[ebp-0x18]     ; output pointer  
101091B8  mov ecx,[edx]          ; next encrypted dword
101091BA  mov edx,[ebp-0x2c]     ; v1 result
101091BD  xor ecx,edx            ; decrypt
101091BF  mov edx,[ebp-0x18]
101091C2  mov [edx],ecx          ; store
101091C4  add dword [ebp-0x18],0x4
\`\`\`

### Phase 7: Exit/Restore

\`\`\`asm
101091EA  pop edi                ; Restore all registers
101091EB  pop esi
101091EC  pop ebp
101091ED  pop esp
101091EE  pop ebx
101091EF  pop edx
101091F0  pop ecx
101091F1  pop eax
101091F2  popf                   ; Restore flags
; ... then jump to real entry point
\`\`\`

---

## Summary

The Themida protection uses:

1. **XTEA Encryption** with:
   - Key: \`E2E4D222 408EC6B5 F6BD5EC7 0614B34A\`
   - Delta: \`0x9E3779B9\` (standard XTEA)
   - 32 rounds per 64-bit block

2. **Position-Independent Code** with call/pop trick for base address calculation

3. **DllMain Check** - only unpacks on DLL_PROCESS_ATTACH

4. **Multi-layer unpacking** - this is just the first layer; there are likely more

5. **VirtualProtect calls** to make sections writable during unpacking

---

## Implications for SSL Patching

The code we patched at offsets like +0xB1FF in the dumped binary exists AFTER Themida unpacking completes. The unpacker:

1. Decrypts the S3 section
2. Decompresses/decrypts the original .text section  
3. Reconstructs imports
4. Jumps to the real DllMain

Our runtime patcher works because it runs AFTER all this completes.


---

## SSL Verification Analysis (Post-Themida)

### The SSL Problem

After reverse engineering, we discovered TWO separate verification mechanisms:

### 1. OpenSSL verify_mode

Located at SSL_CTX offset `+0x130`. Three locations in code set this to 1:

| Offset | Instruction | Purpose |
|--------|-------------|---------|
| 0xB1FF | `mov [esi+0x130], 1` | Set verify_mode for SSL_CTX |
| 0xB6FC | `mov [edx+0x130], 1` | Set verify_mode for SSL_CTX |
| 0xCB08 | `mov [ebx+0x130], 1` | Set verify_mode for SSL_CTX |

**Patch:** Change `01 00 00 00` to `00 00 00 00` in each instruction.

### 2. Custom X509 Verification Callback

Located at offset `0x4EC5`. This callback handles certificate verification AFTER OpenSSL.

**Accepted Error Codes (jumps to accept path at 0x4FBF):**
- 0x02: X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
- 0x15 (21): X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
- 0x16 (22): X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
- 0x06: X509_V_ERR_CERT_NOT_YET_VALID
- 0x0F (15): X509_V_ERR_CRL_SIGNATURE_FAILURE

**NOT Accepted (causes rejection):**
- 0x12 (18): X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT ← **Our certificate triggers this!**

**Patch Location:** 0x4F29
\`\`\`
Original: 0F 85 A4 01 00 00  (JNZ +0x1A4 to reject path)
Patched:  E9 90 00 00 00 90  (JMP +0x90 to accept path, NOP)
\`\`\`

### Why Previous Patches Failed

Patching just `verify_mode=0` disables OpenSSL's internal verification, but the game has
a CUSTOM callback that still checks the X509 error code. Our self-signed certificate 
triggers error 18 (`DEPTH_ZERO_SELF_SIGNED_CERT`), which was NOT in the whitelist.

### Complete Fix

The `ds2_ssl_bypass.exe` patcher applies BOTH patches:
1. Three verify_mode patches
2. One callback patch

After both patches, the game should accept any certificate including self-signed.

