# Dead Space 2 SSL/TLS Certificate Verification Analysis

## Overview

This document provides a detailed reverse engineering analysis of the X.509 certificate verification callback in Dead Space 2's `activation.x86.dll`. This callback is responsible for validating SSL/TLS certificates during connections to EA's Blaze servers.

## Function Location

| Property | Value |
|----------|-------|
| RVA (in unpacked DLL) | 0x00005AC5 |
| Runtime Address | 0x795E5AC5 (with base 0x795E0000) |
| Function Size | ~575 bytes (0x23F) |
| End Address | 0x795E5D04 |

## Function Signature

```c
// X509 verification callback
// Returns: 1 = accept certificate, 0 or -1 = reject certificate
int ssl_verify_callback(int error_code, int depth);
```

## Arguments

| Register/Stack | Purpose |
|---------------|---------|
| `[ebp+0x08]` (ebx) | X.509 error code from OpenSSL |
| `[ebp+0x0c]` (esi) | Certificate chain depth (0 = leaf cert) |

## Complete Disassembly with Annotations

```asm
; ============================================================
; X509 VERIFICATION CALLBACK
; Function: ssl_verify_callback
; Address: 0x795E5AC5
; ============================================================

; PROLOGUE
795e5ac5:  push   0x10                    ; Stack frame size
795e5ac7:  push   0x79675ec8              ; SEH handler address
795e5acc:  call   0x795e4fd0              ; __SEH_prolog

; INITIALIZE LOCAL VARIABLES
795e5ad1:  and    DWORD PTR [ebp-0x20],0x0  ; [ebp-0x20] = error_flag = 0
795e5ad5:  mov    esi,DWORD PTR [ebp+0xc]   ; ESI = depth
795e5ad8:  mov    ebx,DWORD PTR [ebp+0x8]   ; EBX = error_code

; ============================================================
; SECTION 1: DEPTH CHECKS
; Reject certificates at depth 3 or 4
; ============================================================

795e5adb:  cmp    esi,0x4                 ; if (depth == 4)
795e5ade:  je     0x795e5cd3              ;     goto REJECT_PATH

795e5ae4:  cmp    esi,0x3                 ; if (depth == 3)
795e5ae7:  je     0x795e5cd3              ;     goto REJECT_PATH

; ============================================================
; SECTION 2: ERROR CODE ROUTING
; Different handlers for different error types
; ============================================================

795e5aed:  push   0x2
795e5aef:  pop    edi                     ; EDI = 2 (used for comparisons)

; --- Group A: Errors routed to SPECIAL_HANDLER (0x5bbf) ---
; These errors trigger certificate caching/recording logic

795e5af0:  cmp    ebx,edi                 ; error == 2 (UNABLE_TO_GET_ISSUER_CERT)
795e5af2:  je     0x795e5bbf              ;     goto SPECIAL_HANDLER

795e5af8:  cmp    ebx,0x15                ; error == 21 (UNABLE_TO_VERIFY_LEAF_SIGNATURE)
795e5afb:  je     0x795e5bbf              ;     goto SPECIAL_HANDLER

795e5b01:  cmp    ebx,0x16                ; error == 22 (CERT_CHAIN_TOO_LONG)
795e5b04:  je     0x795e5bbf              ;     goto SPECIAL_HANDLER

795e5b0a:  cmp    ebx,0x6                 ; error == 6 (CERT_NOT_YET_VALID)
795e5b0d:  je     0x795e5bbf              ;     goto SPECIAL_HANDLER

795e5b13:  cmp    ebx,0xf                 ; error == 15 (CRL_SIGNATURE_FAILURE)
795e5b16:  je     0x795e5bbf              ;     goto SPECIAL_HANDLER

; --- Group B: Errors routed to LOOKUP_HANDLER (0x5b2f) ---
; These errors check against a whitelist

795e5b1c:  cmp    ebx,0x8                 ; error == 8 (UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
795e5b1f:  je     0x795e5b2f              ;     goto LOOKUP_HANDLER

795e5b21:  cmp    ebx,0x4                 ; error == 4 (UNABLE_TO_DECRYPT_CRL_SIGNATURE)
795e5b24:  je     0x795e5b2f              ;     goto LOOKUP_HANDLER

795e5b26:  cmp    ebx,0xb                 ; error == 11 (UNABLE_TO_GET_CRL)
795e5b29:  jne    0x795e5cd3              ;     else goto REJECT_PATH
                                          ; *** THIS IS THE CRITICAL JUMP ***
                                          ; Error 0x12 (18) falls through here!

; ============================================================
; LOOKUP_HANDLER (0x795e5b2f)
; Checks if error is in a whitelist
; ============================================================

795e5b2f:  call   0x795e443e              ; get_ssl_context()
795e5b34:  mov    esi,eax                 ; ESI = ssl_context
795e5b36:  test   esi,esi
795e5b38:  je     0x795e5cd3              ; if (!ssl_context) goto REJECT

795e5b3e:  mov    edi,0x79651d10          ; default whitelist address
795e5b43:  cmp    DWORD PTR [esi+0x5c],edi
795e5b46:  jne    0x795e5b6f              ; if already initialized, skip

; Initialize whitelist
795e5b48:  push   DWORD PTR ds:0x79651da8 ; whitelist size
795e5b4e:  call   0x795e47e9              ; allocate_memory()
795e5b53:  pop    ecx
795e5b54:  mov    DWORD PTR [esi+0x5c],eax
795e5b57:  test   eax,eax
795e5b59:  je     0x795e5cd3              ; if allocation failed, reject

795e5b5f:  push   DWORD PTR ds:0x79651da8
795e5b65:  push   edi
795e5b66:  push   eax
795e5b67:  call   0x795e71c0              ; memcpy(whitelist)
795e5b6c:  add    esp,0xc

; Check if error code is in whitelist
795e5b6f:  push   DWORD PTR [esi+0x5c]    ; whitelist
795e5b72:  mov    edx,ebx                 ; error_code
795e5b74:  call   0x795e5a81              ; lookup_error_in_whitelist()
795e5b79:  pop    ecx
795e5b7a:  test   eax,eax
795e5b7c:  je     0x795e5cd3              ; if not found, REJECT

; Error found in whitelist - prepare return value
795e5b82:  mov    ecx,DWORD PTR [eax+0x8] ; get associated return value
795e5b85:  mov    DWORD PTR [ebp-0x1c],ecx ; save to local
795e5b88:  mov    ecx,DWORD PTR [ebp+0xc] ; get depth
795e5b8b:  cmp    ecx,0x2
795e5b8e:  je     0x795e5cc2              ; if depth == 2, goto SUCCESS_RETURN

; Update whitelist entry
795e5b94:  add    eax,0x4
795e5b97:  jmp    0x795e5bb6

795e5b99:  mov    DWORD PTR [eax+0x4],ecx
795e5b9c:  add    eax,0xc
795e5b9f:  mov    edx,DWORD PTR ds:0x79651dac
795e5ba5:  imul   edx,edx,0xc
795e5ba8:  add    edx,DWORD PTR [esi+0x5c]
795e5bab:  lea    edi,[eax-0x4]
795e5bae:  cmp    edi,edx
795e5bb0:  jae    0x795e5cc2              ; bounds check
795e5bb6:  cmp    DWORD PTR [eax],ebx     ; find matching entry
795e5bb8:  je     0x795e5b99
795e5bba:  jmp    0x795e5cc2              ; goto SUCCESS_RETURN

; ============================================================
; SPECIAL_HANDLER (0x795e5bbf)
; Records certificate errors for later processing
; ============================================================

795e5bbf:  push   0x0
795e5bc1:  call   0x795e5765              ; some_ssl_function()
795e5bc6:  pop    ecx
795e5bc7:  and    DWORD PTR [ebp-0x4],0x0

795e5bcb:  cmp    ebx,edi                 ; if error == 2
795e5bcd:  je     0x795e5bd4
795e5bcf:  cmp    ebx,0x15                ; or error == 21
795e5bd2:  jne    0x795e5c12

; Handle errors 2 and 21 (issuer cert problems)
795e5bd4:  cmp    DWORD PTR ds:0x7967af88,0x0
795e5bdb:  jne    0x795e5c12

795e5bdd:  push   0x1
795e5bdf:  push   0x795e4de5              ; callback function
795e5be4:  call   DWORD PTR ds:0x796510f4 ; CreateThread/callback
795e5bea:  xor    ecx,ecx
795e5bec:  inc    ecx
795e5bed:  cmp    eax,ecx
795e5bef:  jne    0x795e5bf9
795e5bf1:  mov    DWORD PTR ds:0x7967af88,ecx
795e5bf7:  jmp    0x795e5c12

795e5bf9:  call   0x795e3dcb
795e5bfe:  mov    esi,eax
795e5c00:  call   DWORD PTR ds:0x79651048 ; GetLastError
795e5c06:  mov    DWORD PTR [esi],eax
795e5c08:  mov    DWORD PTR [ebp-0x20],0x1 ; Set error flag
795e5c0f:  mov    esi,DWORD PTR [ebp+0xc]

; Error code switch for recording
795e5c12:  mov    eax,ebx
795e5c14:  sub    eax,edi                 ; error - 2

795e5c16:  je     0x795e5c91              ; error == 2
795e5c18:  sub    eax,0x4
795e5c1b:  je     0x795e5c2e              ; error == 6
795e5c1d:  sub    eax,0x9
795e5c20:  je     0x795e5c70              ; error == 15
795e5c22:  sub    eax,0x6
795e5c25:  je     0x795e5c4f              ; error == 21
795e5c27:  dec    eax
795e5c28:  jne    0x795e5cb0              ; error == 22

; Store depth for each error type
795e5c2e:  push   DWORD PTR ds:0x7967af80 ; error 6 storage
795e5c34:  call   DWORD PTR ds:0x7965105c
795e5c3a:  mov    DWORD PTR [ebp-0x1c],eax
795e5c3d:  cmp    esi,edi
795e5c3f:  je     0x795e5cb0
795e5c41:  push   esi
795e5c42:  call   DWORD PTR ds:0x79651078
795e5c48:  mov    ds:0x7967af80,eax
795e5c4d:  jmp    0x795e5cb0

; [Similar blocks for errors 15, 21, 2...]

; ============================================================
; PRE-RETURN PROCESSING
; ============================================================

795e5cb0:  mov    DWORD PTR [ebp-0x4],0xfffffffe
795e5cb7:  call   0x795e5cca              ; cleanup function
795e5cbc:  cmp    DWORD PTR [ebp-0x20],0x0 ; check error_flag
795e5cc0:  jne    0x795e5cd3              ; if error, goto REJECT

; ============================================================
; SUCCESS_RETURN (0x795e5cc2)
; Returns the stored/calculated value (accepts certificate)
; ============================================================

795e5cc2:  mov    eax,DWORD PTR [ebp-0x1c] ; Load return value
795e5cc5:  jmp    0x795e5cff               ; goto EPILOGUE

; (Helper function at 0x795e5cca)
795e5cc7:  mov    ebx,DWORD PTR [ebp+0x8]
795e5cca:  push   0x0
795e5ccc:  call   0x795e568c
795e5cd1:  pop    ecx
795e5cd2:  ret

; ============================================================
; REJECT_PATH (0x795e5cd3)
; Additional error filtering before final rejection
; ============================================================

795e5cd3:  cmp    ebx,0x1                 ; error == 1 (UNSPECIFIED)
795e5cd6:  je     0x795e5cfc              ;     -> RETURN_FAILURE

795e5cd8:  cmp    ebx,0x3                 ; error == 3 (CRL_NOT_YET_VALID)
795e5cdb:  je     0x795e5cfc              ;     -> RETURN_FAILURE

795e5cdd:  cmp    ebx,0xd                 ; error == 13 (CERT_REVOKED)
795e5ce0:  je     0x795e5cfc              ;     -> RETURN_FAILURE

795e5ce2:  cmp    ebx,0xf                 ; error <= 15
795e5ce5:  jle    0x795e5cec              ;     -> SET_ERRNO

795e5ce7:  cmp    ebx,0x11                ; error <= 17
795e5cea:  jle    0x795e5cfc              ;     -> RETURN_FAILURE
                                          ; *** ERROR 18 (0x12) FALLS THROUGH HERE ***

; SET_ERRNO - set errno to EINVAL (22)
795e5cec:  call   0x795e3db8              ; __errno_location()
795e5cf1:  mov    DWORD PTR [eax],0x16    ; errno = 22 (EINVAL)
795e5cf7:  call   0x795e5922              ; __set_error_mode()

; ============================================================
; RETURN_FAILURE (0x795e5cfc)
; Returns -1 (reject certificate)
; ============================================================

795e5cfc:  or     eax,0xffffffff          ; EAX = -1

; ============================================================
; EPILOGUE (0x795e5cff)
; ============================================================

795e5cff:  call   0x795e5015              ; __SEH_epilog
795e5d04:  ret
```

## Error Code Reference (OpenSSL X509_V_ERR_*)

| Code | Hex | Name | Handler |
|------|-----|------|---------|
| 1 | 0x01 | X509_V_ERR_UNSPECIFIED | REJECT |
| 2 | 0x02 | X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT | SPECIAL |
| 3 | 0x03 | X509_V_ERR_UNABLE_TO_GET_CRL | REJECT |
| 4 | 0x04 | X509_V_ERR_UNABLE_TO_DECRYPT_CRL_SIGNATURE | LOOKUP |
| 6 | 0x06 | X509_V_ERR_CERT_NOT_YET_VALID | SPECIAL |
| 8 | 0x08 | X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY | LOOKUP |
| 11 | 0x0B | X509_V_ERR_UNABLE_TO_GET_CRL | LOOKUP |
| 13 | 0x0D | X509_V_ERR_CERT_REVOKED | REJECT |
| 15 | 0x0F | X509_V_ERR_CRL_SIGNATURE_FAILURE | SPECIAL |
| 16 | 0x10 | X509_V_ERR_ERROR_IN_CRL_NEXT_UPDATE_FIELD | REJECT |
| 17 | 0x11 | X509_V_ERR_CRL_HAS_EXPIRED | REJECT |
| **18** | **0x12** | **X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT** | **REJECT** |
| 21 | 0x15 | X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE | SPECIAL |
| 22 | 0x16 | X509_V_ERR_CERT_CHAIN_TOO_LONG | SPECIAL |

## The Self-Signed Certificate Problem

### Error Flow for Error 0x12 (Self-Signed Cert)

```
ssl_verify_callback(error=0x12, depth=0)
    │
    ├─ Check depth == 4? NO
    ├─ Check depth == 3? NO
    │
    ├─ Check error == 2?  NO
    ├─ Check error == 21? NO
    ├─ Check error == 22? NO
    ├─ Check error == 6?  NO
    ├─ Check error == 15? NO
    │
    ├─ Check error == 8?  NO
    ├─ Check error == 4?  NO
    ├─ Check error == 11? NO ──────> JNE to REJECT_PATH (0x5cd3)
    │
    └─ At REJECT_PATH:
        ├─ Check error == 1?  NO
        ├─ Check error == 3?  NO
        ├─ Check error == 13? NO
        ├─ Check error <= 15? NO (18 > 15)
        ├─ Check error <= 17? NO (18 > 17)
        │
        └─ Falls through to SET_ERRNO
            ├─ errno = 22 (EINVAL)
            └─ RETURN_FAILURE: return -1
```

### Why This Happens

1. The callback is designed to handle **specific known error codes**
2. Error 0x12 (self-signed cert) is **NOT** in any whitelist
3. The code has a "catch-all" that rejects unknown errors
4. Self-signed certificates were never expected in EA's production environment

## Patching Strategy

### Option 1: NOP the JNE at 0x795e5b29

This makes all unknown errors fall through to the LOOKUP_HANDLER:

```
Original: 0F 85 A4 01 00 00  (jne 0x795e5cd3)
Patched:  90 90 90 90 90 90  (nop nop nop nop nop nop)
```

**Problem**: LOOKUP_HANDLER may still reject if error not in whitelist.

### Option 2: Patch the Return Value at 0x795e5cfc

Change `or eax, -1` to `xor eax, eax; inc eax` (return 1):

```
Original: 83 C8 FF        (or eax, 0xffffffff)
Patched:  31 C0 40        (xor eax, eax; inc eax)
```

**Effect**: All rejected certificates now return success.

### Option 3: Add Error 0x12 to Whitelist

Modify the whitelist data at runtime to include error 0x12.

**Complex**: Requires finding and modifying the whitelist structure.

### Option 4: Early Return for Error 0x12

Insert a check at function start:

```asm
cmp ebx, 0x12          ; is this self-signed error?
je success             ; jump to success path
```

**Requires**: Finding space for patch or using a code cave.

## Recommended Patch

The safest patch combines Options 1 and 2:

1. **NOP the JNE at 0x5b29** - allows self-signed error to reach handler
2. **Patch return -1 to return 1** - ensures acceptance even if handler rejects

### Patch Locations (Relative to Module Base)

| Offset | Original | Patched | Description |
|--------|----------|---------|-------------|
| 0x5B29 | 0F 85 A4 01 00 00 | 90 90 90 90 90 90 | NOP the JNE |
| 0x5CFC | 83 C8 FF | 31 C0 40 | Return 1 instead of -1 |

### Pattern Matching for Dynamic Patching

Since the DLL may load at different base addresses, use these patterns:

**Pattern for JNE:**
```
83 FB 04 74 09 83 FB 0B 0F 85
```
(cmp ebx,4; je +9; cmp ebx,0xb; jne ...)

**Pattern for Return:**
```
83 C8 FF E8
```
(or eax,-1; call ...)

## Global Variables

| Address | Purpose |
|---------|---------|
| 0x7967af78 | Error 2 depth storage |
| 0x7967af7c | Error 21 depth storage |
| 0x7967af80 | Error 6 depth storage |
| 0x7967af84 | Error 15 depth storage |
| 0x7967af88 | Thread creation flag |
| 0x79651d10 | Default whitelist address |
| 0x79651da8 | Whitelist size |
| 0x79651dac | Whitelist entry count |

## Related Functions

| Address | Purpose |
|---------|---------|
| 0x795e443e | Get SSL context |
| 0x795e47e9 | Allocate memory |
| 0x795e5a81 | Lookup error in whitelist |
| 0x795e5765 | SSL helper function |
| 0x795e71c0 | Memory copy |
| 0x795e4fd0 | SEH prolog |
| 0x795e5015 | SEH epilog |
| 0x795e3db8 | Get errno pointer |
| 0x795e5922 | Set error mode |
