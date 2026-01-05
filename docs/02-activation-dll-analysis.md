# Activation DLL .text Section Analysis

Complete reverse engineering documentation for the decrypted `.text` section of `activation.x86.dll` (Dead Space 2, 2011).

## Overview

| Property | Value |
|----------|-------|
| Section | .text |
| Virtual Address | 0x10001000 - 0x10070FFF |
| Size | 458,752 bytes (458 KB) |
| Functions | 188 |
| Entropy | 3.25 (decrypted code) |
| Compiler | MSVC 10.0 (Visual Studio 2010) |

---

## Table of Contents

1. [Exported Functions](#exported-functions)
2. [Function Categories](#function-categories)
3. [Complete Function Reference](#complete-function-reference)
4. [Critical Function Analysis](#critical-function-analysis)
5. [C Runtime Library Functions](#c-runtime-library-functions)
6. [Memory Management](#memory-management)
7. [String Operations](#string-operations)
8. [Activation Logic](#activation-logic)
9. [Data Structures](#data-structures)

---

## Exported Functions

The DLL exports 6 functions (internal name: `drmlib.dll`):

| Ordinal | Name | RVA | VA | Description |
|---------|------|-----|-----|-------------|
| 1 | `?Padding1@@YAKXZ` | 0x1610 | 0x10001610 | Debug stub (returns 0xDEAD0001) |
| 2 | `?Padding2@@YAKXZ` | 0x25B0 | 0x100025B0 | Debug stub (returns 0xDEAD0002) |
| 3 | `?Padding3@@YAKXZ` | 0x25C0 | 0x100025C0 | Debug stub (returns 0xDEAD0003) |
| 4 | `?Padding4@@YAKXZ` | 0x25D0 | 0x10002840 | Debug stub (returns 0xDEAD0004) |
| 5 | `f2` | 0x25D0 | 0x100025D0 | Alternate entry point |
| 6 | `start` | 0x1620 | 0x10001620 | **Main entry point** |

### Export Analysis

#### DllMain (0x10001000)

```asm
push    ebp
mov     ebp, esp
mov     eax, [ebp+0xC]      ; fdwReason
test    eax, eax            ; DLL_PROCESS_ATTACH = 0?
je      return_true
cmp     eax, 2              ; DLL_PROCESS_DETACH = 2
ja      return_true
mov     eax, [ebp+8]        ; hinstDLL
push    eax
call    [init_function]     ; 0x79651190 (runtime resolved)
return_true:
mov     eax, 1              ; TRUE
pop     ebp
ret     0xC                 ; stdcall, 3 params
```

- Handles `DLL_PROCESS_ATTACH` (1) and `DLL_PROCESS_DETACH` (2)
- Calls internal initialization function
- Always returns TRUE

#### start (0x10001620) - Main Entry

```asm
push    0x51DCE5            ; Magic/identifier
jmp     fcn.101091f8        ; Jump to S3 unpacker
```

The game calls `start()` which jumps to the S3 unpacker code. After unpacking completes, control returns to the actual activation logic in .text.

#### f2 (0x100025D0) - Alternate Entry

```asm
push    0x507D00            ; Different magic value
jmp     fcn.101091f8        ; Same unpacker target
```

Secondary entry point, possibly for different activation modes.

#### Padding Functions

All four padding functions are simple stubs:
```asm
mov     eax, 0xDEAD000X     ; X = ordinal number
ret
```

These return "dead" markers (0xDEAD0001-0004), likely debug stubs or placeholders.

---

## Function Categories

### Summary by Category

| Category | Count | Size Range |
|----------|-------|------------|
| C Runtime Library | ~45 | 6-669 bytes |
| Memory Management | ~20 | 6-332 bytes |
| String Operations | ~25 | 9-431 bytes |
| Activation/License | ~15 | 70-887 bytes |
| Error Handling | ~10 | 8-277 bytes |
| Helper Functions | ~30 | 3-50 bytes |
| Initialization | ~15 | 20-220 bytes |
| Unknown/Obfuscated | ~28 | varies |

---

## Complete Function Reference

### Functions 0x10001000 - 0x10001FFF

| Address | BBs | Size | Name/Purpose |
|---------|-----|------|--------------|
| 0x10001000 | 4 | 34 | **DllMain** - DLL entry point |
| 0x10001030 | 6 | 133 | COM object initialization |
| 0x100010c0 | 8 | 149 | COM object creation |
| 0x10001160 | 10 | 71 | Object destructor/release |
| 0x10001610 | 1 | 6 | **Padding1** - returns 0xDEAD0001 |
| 0x10001620 | 1 | 10 | **start** - main entry (jumps to S3) |

### Functions 0x10002000 - 0x10002FFF

| Address | BBs | Size | Name/Purpose |
|---------|-----|------|--------------|
| 0x100025b0 | 1 | 6 | **Padding2** - returns 0xDEAD0002 |
| 0x100025c0 | 1 | 6 | **Padding3** - returns 0xDEAD0003 |
| 0x100025d0 | 1 | 10 | **f2** - alternate entry (jumps to S3) |
| 0x10002840 | 1 | 6 | **Padding4** - returns 0xDEAD0004 |
| 0x10002846 | 6 | 277 | **__security_check_cookie** - stack canary check |
| 0x10002855 | 1 | 11 | HeapFree wrapper |
| 0x100028af | 7 | 128 | **malloc** - heap allocation |
| 0x1000292f | 18 | 173 | Memory block manager |
| 0x100029dc | 16 | 148 | Heap allocation with retry |
| 0x10002a70 | 4 | 58 | **free** - heap deallocation |
| 0x10002aaa | 28 | 332 | CRT initialization |
| 0x10002b83 | 4 | 20 | Get process heap |
| 0x10002c0e | 23 | 226 | Thread local storage init |
| 0x10002e2d | 1 | 29 | Lock initialization |
| 0x10002e57 | 5 | 64 | Critical section wrapper |
| 0x10002e97 | 3 | 30 | Lock helper |
| 0x10002eb5 | 1 | 39 | Unlock helper |
| 0x10002edc | 5 | 53 | EnterCriticalSection wrapper |
| 0x10002f11 | 1 | 11 | TLS value getter |
| 0x10002f43 | 1 | 37 | TLS initialization |
| 0x10002f68 | 1 | 16 | TLS index getter |
| 0x10002f99 | 1 | 32 | TLS data setter |
| 0x10002fb9 | 13 | 182 | **_initterm** - init/term tables |

### Functions 0x10003000 - 0x10003FFF

| Address | BBs | Size | Name/Purpose |
|---------|-----|------|--------------|
| 0x100030a0 | 1 | 54 | **atexit** - register exit handler |
| 0x100030d6 | 1 | 6 | Return zero |
| 0x100030dc | 1 | 23 | Register cleanup handler |
| 0x100030f3 | 1 | 15 | Exit flag check |
| 0x10003102 | 4 | 40 | New handler |
| 0x1000312a | 4 | 76 | Exception throw |
| 0x10003176 | 7 | 66 | **GetLastError** wrapper |
| 0x100031b8 | 3 | 19 | **errno** location getter |
| 0x100031cb | 3 | 19 | **_doserrno** location getter |
| 0x100031de | 1 | 35 | Set errno from Win32 error |
| 0x10003201 | 1 | 30 | Error code mapper |
| 0x1000321f | 1 | 20 | Map error helper |
| 0x10003233 | 4 | 43 | Error lookup |
| 0x1000325e | 1 | 24 | DOS error setter |
| 0x10003276 | 1 | 9 | Return errno address |
| 0x1000327f | 1 | 9 | Return doserrno address |
| 0x10003288 | 1 | 51 | Wide char error setter |
| 0x100032bb | 7 | 36 | **_invalid_parameter** |
| 0x100032df | 13 | 151 | Invalid parameter handler |
| 0x10003376 | 26 | 320 | **snprintf** variant |
| 0x100034b6 | 1 | 22 | Format specifier handler |
| 0x100034cc | 1 | 15 | Return argument |
| 0x100034db | 1 | 30 | Format width handler |
| 0x100034f9 | 5 | 38 | Locale-aware formatter |
| 0x1000351f | 23 | 431 | **Main activation path setup** |
| 0x100036ce | 5 | 57 | Path construction |
| 0x10003707 | 1 | 9 | Get OS version info |
| 0x10003719 | 3 | 52 | Version comparison |
| 0x1000374d | 16 | 148 | Version string builder |
| 0x1000378a | 3 | 156 | Wide string helper |
| 0x1000382c | 1 | 9 | Return constant |
| 0x10003835 | 1 | 9 | Return constant |
| 0x1000383e | 6 | 121 | String format |
| 0x100038b7 | 3 | 26 | Buffer helper |
| 0x100038d1 | 28 | 279 | **License file path builder** |
| 0x100039eb | 1 | 9 | Return constant |
| 0x100039f7 | 1 | 9 | Return constant |
| 0x10003a00 | 9 | 110 | Path normalization |
| 0x10003a6e | 17 | 379 | **Path combination** |
| 0x10003be9 | 7 | 69 | Path validation |
| 0x10003c2e | 7 | 76 | **VirtualAlloc** wrapper |
| 0x10003c7a | 8 | 78 | Memory protection |
| 0x10003cc8 | 8 | 82 | Memory query |
| 0x10003d1a | 49 | 581 | **Socket/handle initialization** |
| 0x10003f5f | 10 | 83 | Handle cleanup |
| 0x10003fb2 | 21 | 220 | Resource loader |

### Functions 0x10004000 - 0x10004FFF

| Address | BBs | Size | Name/Purpose |
|---------|-----|------|--------------|
| 0x1000408e | 61 | 410 | **Registry operations** |
| 0x10004228 | 12 | 187 | Registry key reader |
| 0x100042e3 | 13 | 151 | Registry value writer |
| 0x1000437a | 5 | 38 | Registry cleanup |
| 0x100043d0 | 1 | 69 | File attribute checker |
| 0x10004415 | 1 | 20 | File exists check |
| 0x100045bf | 40 | 330 | **File operations manager** |
| 0x10004709 | 3 | 32 | Get file size |
| 0x10004729 | 9 | 155 | File read |
| 0x100047c4 | 1 | 8 | **_amsg_exit** - abort message |
| 0x100047cc | 13 | 95 | Exit with message |
| 0x10004830 | 14 | 139 | **strlen** |
| 0x100048bb | 8 | 103 | **wcslen** |
| 0x10004922 | 1 | 9 | Return string end |
| 0x10004930 | 21 | 135 | **strcmp** |
| 0x100049b8 | 3 | 51 | **strncmp** |
| 0x100049eb | 7 | 74 | **_stricmp** (case-insensitive) |
| 0x10004a8c | 1 | 23 | Character comparison |
| 0x10004aa3 | 13 | 185 | **strcpy** |
| 0x10004b5c | 1 | 9 | Return dest |
| 0x10004b65 | 4 | 51 | **strcat** |
| 0x10004b98 | 1 | 15 | String append end |
| 0x10004ba7 | 7 | 297 | **sprintf** variant |
| 0x10004cd0 | 1 | 37 | MessageBox wrapper |
| 0x10004cf5 | 3 | 45 | Show error dialog |
| 0x10004d22 | 1 | 16 | **__fpecode** - FP exception code |
| 0x10004d32 | 4 | 50 | FP error handler |
| 0x10004d6b | 3 | 19 | Thread ID getter |
| 0x10004d7e | 4 | 49 | Locale ID getter |
| 0x10004db6 | 1 | 17 | Heap flags getter |
| 0x10004dc7 | 1 | 30 | Stack base getter |
| 0x10004e61 | 1 | 8 | Return zero |
| 0x10004e81 | 7 | 55 | Fiber local storage |
| 0x10004eb8 | 1 | 13 | Return constant |
| 0x10004ec5 | 49 | 564 | **Environment variable handler** |

### Functions 0x10005000 - 0x10005FFF

| Address | BBs | Size | Name/Purpose |
|---------|-----|------|--------------|
| 0x100050ca | 1 | 9 | Return envp |
| 0x10005105 | 43 | 398 | **GetEnvironmentVariable** wrapper |
| 0x1000526c | 3 | 15 | Environment cleanup |
| 0x100052a8 | 1 | 15 | Wide env getter |
| 0x100052b7 | 1 | 15 | ANSI env getter |
| 0x100052c6 | 3 | 35 | **_get_environ** |
| 0x100052f0 | 4 | 53 | Environ initialization |
| 0x10005330 | 7 | 68 | **_putenv** |
| 0x10005380 | 4 | 166 | **setenv** variant |
| 0x1000543c | 23 | 364 | **CreateProcess wrapper** |
| 0x100055a8 | 16 | 117 | **String format (snwprintf)** |
| 0x1000561d | 28 | 205 | Wide string formatter |
| 0x100056ea | 3 | 27 | String length helper |
| 0x10005705 | 12 | 99 | **wcscpy** variant |
| 0x10005768 | 6 | 63 | **GetVersion** checker |
| 0x100057a7 | 17 | 143 | **Module handle getter** |
| 0x10005836 | 19 | 153 | **GetModuleFileName** wrapper |
| 0x100058cf | 28 | 331 | **Structure deallocator** |
| 0x10005a1a | 10 | 77 | Object cleanup |
| 0x10005a67 | 7 | 109 | Buffer cleanup |
| 0x10005ad4 | 1 | 12 | Return zero |
| 0x10005ae0 | 9 | 47 | Pointer array cleanup |
| 0x10005b0f | 5 | 100 | Handle array close |
| 0x10005b73 | 26 | 400 | **WideCharToMultiByte** wrapper |
| 0x10005d03 | 13 | 152 | **MultiByteToWideChar** wrapper |
| 0x10005d9e | 1 | 9 | Return input |
| 0x10005da7 | 11 | 135 | **Locale initializer** |
| 0x10005e2e | 12 | 124 | Locale cleanup |
| 0x10005eaa | 37 | 489 | **Code page handler** |

### Functions 0x10006000 - 0x10006FFF

| Address | BBs | Size | Name/Purpose |
|---------|-----|------|--------------|
| 0x10006093 | 27 | 399 | **Multibyte string handler** |
| 0x100061f4 | 1 | 9 | Return locale |
| 0x1000622d | 3 | 30 | Get code page |
| 0x1000624b | 15 | 130 | Charset conversion |
| 0x100062cd | 10 | 110 | Char type lookup |
| 0x1000633b | 9 | 83 | MB/WC conversion |
| 0x1000638e | 1 | 24 | Return charset |
| 0x100063b0 | 7 | 144 | **isprint/isspace** check |
| 0x100064a2 | 1 | 23 | Is printable (ANSI) |
| 0x100064b9 | 1 | 25 | Is space (ANSI) |
| 0x100064d2 | 1 | 25 | Is digit (ANSI) |
| 0x100064eb | 1 | 23 | Is alpha (ANSI) |
| 0x10006510 | 33 | 305 | **memset** (SSE optimized) |
| 0x1000658a | 5 | 51 | **memset** (small buffer) |
| 0x100065c0 | 39 | 465 | **memcpy** (SSE optimized) |
| 0x10006921 | 28 | 181 | **memmove** |
| 0x100069d6 | 4 | 32 | **memcmp** |
| 0x100069ff | 3 | 887 | **Large structure deallocator** |
| 0x10006d76 | 12 | 105 | Crypto context cleanup |
| 0x10006ddf | 28 | 254 | Hash context cleanup |
| 0x10006edd | 47 | 487 | **String/buffer cleanup** |

### Functions 0x10007000 - 0x10007FFF

| Address | BBs | Size | Name/Purpose |
|---------|-----|------|--------------|
| 0x100070c4 | 3 | 70 | Array cleanup |
| 0x1000710a | 18 | 231 | String array free |
| 0x100071f1 | 3 | 64 | Object reference decrement |
| 0x100072a5 | 8 | 132 | **HeapReAlloc** wrapper |
| 0x1000734c | 1 | 9 | Return constant |
| 0x10007355 | 2 | 31 | Debug stub |
| 0x10007374 | 1 | 3 | **ret** (return instruction) |
| 0x10007380 | 11 | 149 | **toupper/tolower** |
| 0x10007415 | 1 | 22 | Character classify |
| 0x1000742b | 1 | 11 | Char type getter |
| 0x10007610 | 1 | 22 | Wide char classify |
| 0x1000763c | 75 | 555 | **strtol** (string to long) |
| 0x10007867 | 4 | 43 | **atoi** |
| 0x10007892 | 4 | 44 | **atol** |
| 0x100078be | 77 | 669 | **strtoul** (unsigned long) |
| 0x10007b5b | 4 | 43 | **_wtoi** (wide atoi) |
| 0x10007b90 | 4 | 43 | **_wtol** (wide atol) |
| 0x10007bbb | 13 | 184 | **iswctype** - wide char type |
| 0x10007c80 | 3 | 52 | **iswalpha** |
| 0x10007cb4 | 3 | 56 | **iswdigit** |
| 0x10007cec | 1 | 19 | Character validation |
| 0x10007cff | 4 | 38 | Wide char helper |
| 0x10007d76 | 30 | 192 | **printf** format parser |
| 0x10007e40 | 8 | 64 | Output character |
| 0x10007e80 | 8 | 85 | Output string |
| 0x10007ed5 | 8 | 57 | Output padding |
| 0x10007f0e | 18 | 192 | Format handler |
| 0x10007fce | 6 | 71 | Numeric formatter |

---

## Critical Function Analysis

### fcn.1000351f - Main Activation Path Setup (0x1000351f)

**Size**: 431 bytes | **Basic Blocks**: 23

This is a key function that sets up the activation path and calls the license validation chain.

```c
// Pseudo-code reconstruction
int activation_path_setup(int arg) {
    char path_buffer[0x314];  // 788 bytes
    char module_path[0x104];  // 260 bytes
    
    // Get some formatted path
    result = format_path(arg);
    if (!result) return 0;
    
    // Check version flag
    if (check_version(3) == 1 || global_flag == 1) {
        // Alternate activation path
        HANDLE hDir = GetStdHandle(STD_OUTPUT_HANDLE);  // -12
        // ... path operations
    }
    
    // Build path: %s\Solidshield\%s\activ.dat
    if (string_format(path_buffer, 0x314, path_template, ...) != 0) {
        // Error case
        show_error(0, 0, 0, 0, 0);
        return;
    }
    
    // Get module filename
    GetModuleFileNameA(NULL, module_path, 260);
    
    // Continue with path building...
    string_format(path_buffer, 0x314, "...");
    
    // Create process/file operations
    call_file_operations(path_buffer, ...);
    
    return;
}
```

**Key Operations**:
1. Builds Solidshield activation path
2. Gets module filename
3. Performs file existence checks
4. Initiates CreateProcess for activation.exe

### fcn.100038d1 - License File Path Builder (0x100038d1)

**Size**: 279 bytes | **Basic Blocks**: 28

Constructs the path to the license file (`activ.dat`).

**Path Template**: `%s\Solidshield\%s\activ.dat`
- First `%s`: User's AppData folder
- Second `%s`: Game/application identifier

### fcn.10003d1a - Socket/Handle Initialization (0x10003d1a)

**Size**: 581 bytes | **Basic Blocks**: 49

Initializes socket descriptors or file handles for network operations.

**Key Features**:
- Allocates 32 socket slots (0x40 bytes each, total 0x800)
- Uses VirtualAlloc for memory
- Initializes each slot with marker values (0xFFFFFFFF, 0x0A00)
- Handles expansion up to 2048+ handles

### fcn.100069ff - Large Structure Deallocator (0x100069ff)

**Size**: 887 bytes | **Basic Blocks**: 3 (linear)

Deallocates a large activation/license context structure (~300+ bytes).

The function calls `free()` (fcn.10002a70) on approximately 80 different structure members, suggesting a complex activation context with:
- Multiple string buffers
- Certificate/key handles
- Network connection handles
- Crypto context handles

**Structure Offsets Freed**:
- 0x00-0x3C: Basic info strings
- 0x40-0x7C: Extended info
- 0x80-0xA8: Crypto contexts
- 0xB0-0xD4: Network handles
- 0xD8-0x118: Additional buffers

---

## C Runtime Library Functions

### Memory Functions

| Address | Function | Signature |
|---------|----------|-----------|
| 0x10006510 | memset | `void* memset(void* dest, int val, size_t count)` |
| 0x100065c0 | memcpy | `void* memcpy(void* dest, void* src, size_t count)` |
| 0x10006921 | memmove | `void* memmove(void* dest, void* src, size_t count)` |
| 0x100069d6 | memcmp | `int memcmp(void* p1, void* p2, size_t count)` |

**Note**: memset and memcpy use SSE optimizations (movdqa) for buffers ≥128 bytes.

### String Functions

| Address | Function | Signature |
|---------|----------|-----------|
| 0x10004830 | strlen | `size_t strlen(const char* str)` |
| 0x100048bb | wcslen | `size_t wcslen(const wchar_t* str)` |
| 0x10004930 | strcmp | `int strcmp(const char* s1, const char* s2)` |
| 0x100049b8 | strncmp | `int strncmp(const char* s1, const char* s2, size_t n)` |
| 0x100049eb | _stricmp | `int _stricmp(const char* s1, const char* s2)` |
| 0x10004aa3 | strcpy | `char* strcpy(char* dest, const char* src)` |
| 0x10004b65 | strcat | `char* strcat(char* dest, const char* src)` |

### Conversion Functions

| Address | Function | Signature |
|---------|----------|-----------|
| 0x10007867 | atoi | `int atoi(const char* str)` |
| 0x10007892 | atol | `long atol(const char* str)` |
| 0x1000763c | strtol | `long strtol(const char* str, char** endptr, int base)` |
| 0x100078be | strtoul | `unsigned long strtoul(const char* str, char** endptr, int base)` |
| 0x10007b5b | _wtoi | `int _wtoi(const wchar_t* str)` |

### Character Classification

| Address | Function | Description |
|---------|----------|-------------|
| 0x10007380 | toupper | Case conversion |
| 0x100063b0 | isprint | Printable character check |
| 0x10007bbb | iswctype | Wide character type check |
| 0x10007c80 | iswalpha | Wide alphabetic check |
| 0x10007cb4 | iswdigit | Wide digit check |

---

## Memory Management

### Heap Operations

| Address | Function | Description |
|---------|----------|-------------|
| 0x100028af | malloc | Heap allocation via HeapAlloc |
| 0x10002a70 | free | Heap deallocation via HeapFree |
| 0x100072a5 | realloc | Heap reallocation |
| 0x10002b83 | get_heap | Get process heap handle |
| 0x10002846 | __security_check_cookie | Stack canary verification |

### Virtual Memory

| Address | Function | Description |
|---------|----------|-------------|
| 0x10003c2e | VirtualAlloc wrapper | Allocate virtual memory |
| 0x10003c7a | VirtualProtect wrapper | Change page protection |
| 0x10003cc8 | VirtualQuery wrapper | Query memory info |

---

## String Operations

### Path Operations

| Address | Function | Description |
|---------|----------|-------------|
| 0x10003a6e | path_combine | Combine path components |
| 0x10003a00 | path_normalize | Normalize path separators |
| 0x10003be9 | path_validate | Validate path string |
| 0x100038d1 | build_license_path | Build activ.dat path |

### Format Functions

| Address | Function | Description |
|---------|----------|-------------|
| 0x10003376 | snprintf variant | Safe string format |
| 0x100055a8 | snwprintf | Wide string format |
| 0x10004ba7 | sprintf variant | String format |
| 0x10007d76 | printf parser | Format string parser |

---

## Activation Logic

### Core Activation Functions

| Address | Size | Description |
|---------|------|-------------|
| 0x1000351f | 431 | Main activation path setup |
| 0x100038d1 | 279 | License file path builder |
| 0x1000543c | 364 | CreateProcess wrapper (activation.exe) |
| 0x1000408e | 410 | Registry operations |
| 0x100045bf | 330 | File operations manager |

### Activation Flow

1. **Initialization** (DllMain → 0x10001000)
   - DLL loaded by game
   - Basic initialization

2. **Entry** (start → 0x10001620)
   - Jumps to S3 unpacker
   - S3 decrypts .text section
   - Returns to activation logic

3. **Path Setup** (0x1000351f)
   - Builds `%APPDATA%\Solidshield\<game>\activ.dat` path
   - Checks if activation file exists

4. **License Check** (0x100045bf area)
   - Reads activ.dat if exists
   - Validates license data

5. **Network Activation** (if needed)
   - Launches activation.exe helper
   - HTTP POST to EA servers
   - Receives signed license

6. **License Write**
   - Writes activ.dat with activation data
   - Hardware fingerprint stored

---

## Data Structures

### Activation Context (inferred from fcn.100069ff)

```c
struct ActivationContext {
    /* 0x000 */ void* info_strings[16];      // Basic info
    /* 0x040 */ void* extended_info[16];     // Extended strings
    /* 0x080 */ void* crypto_ctx[8];         // Crypto handles
    /* 0x0A0 */ void* hash_ctx[4];           // Hash contexts
    /* 0x0B0 */ void* conn_handles[10];      // Connection info
    /* 0x0D8 */ void* buffers[16];           // Data buffers
    // Total: ~0x120 bytes (288 bytes)
};
```

### Socket Slot (from fcn.10003d1a)

```c
struct SocketSlot {
    /* 0x00 */ SOCKET handle;          // -1 if unused
    /* 0x04 */ BYTE flags;             // Connection flags
    /* 0x08 */ DWORD reserved1;
    /* 0x20 */ WORD status;            // 0x0A00 marker
    /* 0x22 */ BYTE more_flags;
    /* 0x30 */ DWORD reserved2;
    /* 0x34 */ BYTE reserved3;
    // Size: 0x40 bytes (64 bytes)
};
```

---

## Analysis Tools Used

- **radare2** 5.9.8 - Function analysis and disassembly
- **objdump** (GNU Binutils 2.45.1) - PE structure analysis
- **strings** - String extraction
- **Python** + pefile, capstone - Custom analysis

---

## Recommendations for Further Analysis

1. **Load in Ghidra/IDA Pro**: Import `dumps/unpacked_activation_fixed.x86.dll`
2. **Focus Areas**:
   - Functions 0x1000351f, 0x100038d1 for activation flow
   - Functions 0x1000408e, 0x100045bf for registry/file operations
   - Functions 0x10003d1a for network initialization
3. **Cross-reference**:
   - All calls to HeapAlloc/HeapFree to understand lifetime
   - String references to find activation URLs
   - Registry key accesses

---

## References

- [Microsoft PE Format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)
- [radare2 Documentation](https://book.rada.re/)
- [Solidshield DRM](https://en.wikipedia.org/wiki/Solidshield)
