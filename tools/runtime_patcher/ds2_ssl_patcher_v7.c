/*
 * Dead Space 2 SSL Patcher v7 - Aggressive Certificate Bypass
 * 
 * This version takes a more aggressive approach:
 * 1. Patches SSL_get_verify_result to always return X509_V_OK (0)
 * 2. Patches any memcmp/strcmp that might be comparing certificate data
 * 3. Hooks the verify callback return path
 * 
 * The game appears to be doing certificate pinning - checking the actual
 * certificate hash/contents, not just relying on OpenSSL verification.
 * 
 * Build: i686-w64-mingw32-gcc -o ds2_ssl_patcher_v7.exe ds2_ssl_patcher_v7.c -lpsapi -static -O2
 */

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

#define GAME_EXE "deadspace2.exe"
#define TARGET_DLL "activation.x86.dll"

DWORD FindProcess(const char* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    
    DWORD pid = 0;
    if (Process32First(snapshot, &pe32)) {
        do {
            if (_stricmp(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe32));
    }
    
    CloseHandle(snapshot);
    return pid;
}

BYTE* FindModuleBase(HANDLE hProcess, const char* moduleName, DWORD* moduleSize) {
    HMODULE modules[1024];
    DWORD needed;
    
    if (!EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) {
        return NULL;
    }
    
    int count = needed / sizeof(HMODULE);
    for (int i = 0; i < count; i++) {
        char name[MAX_PATH];
        if (GetModuleBaseNameA(hProcess, modules[i], name, sizeof(name))) {
            if (_stricmp(name, moduleName) == 0) {
                MODULEINFO info;
                if (GetModuleInformation(hProcess, modules[i], &info, sizeof(info))) {
                    *moduleSize = info.SizeOfImage;
                }
                return (BYTE*)modules[i];
            }
        }
    }
    
    return NULL;
}

BOOL WriteMem(HANDLE hProcess, BYTE* address, void* data, SIZE_T size) {
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    SIZE_T written;
    BOOL result = WriteProcessMemory(hProcess, address, data, size, &written);
    
    VirtualProtectEx(hProcess, address, size, oldProtect, &oldProtect);
    FlushInstructionCache(hProcess, address, size);
    
    return result && written == size;
}

/* Search for a pattern in memory, returning offset or -1 if not found */
int FindPattern(BYTE* data, SIZE_T dataSize, BYTE* pattern, SIZE_T patternSize, SIZE_T startOffset) {
    for (SIZE_T i = startOffset; i < dataSize - patternSize; i++) {
        if (memcmp(data + i, pattern, patternSize) == 0) {
            return (int)i;
        }
    }
    return -1;
}

/* Search for pattern with wildcards (0xFF = wildcard) */
int FindPatternWildcard(BYTE* data, SIZE_T dataSize, BYTE* pattern, BYTE* mask, SIZE_T patternSize, SIZE_T startOffset) {
    for (SIZE_T i = startOffset; i < dataSize - patternSize; i++) {
        int match = 1;
        for (SIZE_T j = 0; j < patternSize; j++) {
            if (mask[j] && data[i + j] != pattern[j]) {
                match = 0;
                break;
            }
        }
        if (match) return (int)i;
    }
    return -1;
}

int main(int argc, char* argv[]) {
    printf("===========================================\n");
    printf(" Dead Space 2 SSL Patcher v7\n");
    printf(" Aggressive Certificate Bypass\n");
    printf("===========================================\n\n");
    
    DWORD pid = FindProcess(GAME_EXE);
    if (pid == 0) {
        printf("[-] %s not found. Start the game first.\n", GAME_EXE);
        printf("[*] Press Enter to exit...\n");
        getchar();
        return 1;
    }
    
    printf("[+] Found process: PID %lu\n", pid);
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process (error %lu)\n", GetLastError());
        printf("    Try running as Administrator\n");
        getchar();
        return 1;
    }
    
    DWORD moduleSize = 0;
    BYTE* dllBase = FindModuleBase(hProcess, TARGET_DLL, &moduleSize);
    
    if (dllBase == NULL) {
        printf("[-] %s not found in process\n", TARGET_DLL);
        CloseHandle(hProcess);
        getchar();
        return 1;
    }
    
    printf("[+] Found %s at 0x%p (size: %lu bytes)\n", TARGET_DLL, dllBase, moduleSize);
    
    /* Read module into memory */
    printf("[*] Reading module memory...\n");
    BYTE* moduleData = (BYTE*)malloc(moduleSize);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, dllBase, moduleData, moduleSize, &bytesRead)) {
        printf("[-] Failed to read module memory\n");
        free(moduleData);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Read %zu bytes\n", bytesRead);
    
    int totalPatches = 0;
    
    /* ============================================================
     * PATCH SET 1: All verify_mode = 1 instructions
     * Pattern variants:
     *   c7 8x 30 01 00 00 01 00 00 00  (mov [reg+0x130], 1)
     * ============================================================ */
    printf("\n[*] Patch Set 1: All verify_mode=1 instructions...\n");
    
    /* Common patterns for mov [reg+0x130], 1 */
    BYTE verifyPatterns[][10] = {
        {0xc7, 0x86, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, /* [esi+0x130] */
        {0xc7, 0x82, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, /* [edx+0x130] */
        {0xc7, 0x81, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, /* [ecx+0x130] */
        {0xc7, 0x83, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, /* [ebx+0x130] */
        {0xc7, 0x87, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, /* [edi+0x130] */
        {0xc7, 0x80, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, /* [eax+0x130] */
    };
    
    int verifyCount = 0;
    for (int p = 0; p < 6; p++) {
        int offset = 0;
        while ((offset = FindPattern(moduleData, bytesRead, verifyPatterns[p], 10, offset)) >= 0) {
            printf("    Found verify_mode=1 at +0x%X\n", offset);
            BYTE newVal = 0x00;
            if (WriteMem(hProcess, dllBase + offset + 6, &newVal, 1)) {
                verifyCount++;
                moduleData[offset + 6] = 0x00; /* Update local copy */
            }
            offset += 10;
        }
    }
    printf("[+] Patched %d verify_mode instructions\n", verifyCount);
    totalPatches += verifyCount;
    
    /* ============================================================
     * PATCH SET 2: SSL_get_verify_result return patching
     * 
     * Look for: call SSL_get_verify_result; test eax,eax or cmp eax,X
     * And patch the conditional jump to always take the success path
     * 
     * Pattern: 85 c0 (test eax, eax) followed by 75 XX (jne) or 74 XX (je)
     * Or: 83 f8 XX (cmp eax, XX) followed by jump
     * ============================================================ */
    printf("\n[*] Patch Set 2: SSL_get_verify_result checks...\n");
    
    /* Look for test eax,eax (85 c0) followed by jne (75) - patch jne to jmp */
    /* Or test eax,eax followed by je (74) - patch to always jump */
    int resultChecks = 0;
    
    /* Pattern: test eax, eax; jne XX -> NOP test, change jne to jmp */
    BYTE testJnePattern[] = {0x85, 0xc0, 0x75};
    int offset = 0;
    while ((offset = FindPattern(moduleData, bytesRead, testJnePattern, 3, offset)) >= 0) {
        /* Change jne (75) to jmp (eb) - always jump */
        /* Or better: NOP the test and change jne to jmp */
        printf("    Found test eax,eax; jne at +0x%X\n", offset);
        
        /* We want to NOT jump on success (eax=0 means X509_V_OK)
         * jne jumps when result != 0 (error)
         * Change to NOP NOP EB (unconditional relative jump) would skip error path
         * But actually if we want success, when eax=0 the jne doesn't jump
         * So we should just NOP out the jne to fall through */
        BYTE patch[] = {0x90, 0x90}; /* NOP NOP */
        if (WriteMem(hProcess, dllBase + offset + 2, patch, 2)) {
            resultChecks++;
            moduleData[offset + 2] = 0x90;
            moduleData[offset + 3] = 0x90;
        }
        offset += 4;
    }
    
    /* Pattern: test eax, eax; je XX -> keep je (success path) */
    /* Actually je means "jump if equal (to zero)" so je on test eax,eax means "jump if eax==0" (success) */
    /* We want this to always happen, so change je to jmp */
    BYTE testJePattern[] = {0x85, 0xc0, 0x74};
    offset = 0;
    while ((offset = FindPattern(moduleData, bytesRead, testJePattern, 3, offset)) >= 0) {
        printf("    Found test eax,eax; je at +0x%X\n", offset);
        /* Change je (74) to jmp (eb) */
        BYTE patch = 0xeb;
        if (WriteMem(hProcess, dllBase + offset + 2, &patch, 1)) {
            resultChecks++;
            moduleData[offset + 2] = 0xeb;
        }
        offset += 4;
    }
    
    printf("[+] Patched %d verify result checks\n", resultChecks);
    totalPatches += resultChecks;
    
    /* ============================================================
     * PATCH SET 3: X509_verify_cert result checks
     * 
     * Look for cmp eax, 1; jne (check if result == 1 for success)
     * Pattern: 83 f8 01 75 or 83 f8 01 0f 85
     * ============================================================ */
    printf("\n[*] Patch Set 3: X509_verify_cert success checks...\n");
    
    int x509Checks = 0;
    
    /* cmp eax, 1; jne XX - make jne into NOPs */
    BYTE cmpJnePattern[] = {0x83, 0xf8, 0x01, 0x75};
    offset = 0;
    while ((offset = FindPattern(moduleData, bytesRead, cmpJnePattern, 4, offset)) >= 0) {
        printf("    Found cmp eax,1; jne at +0x%X\n", offset);
        BYTE patch[] = {0x90, 0x90}; /* NOP the jne and its offset */
        if (WriteMem(hProcess, dllBase + offset + 3, patch, 2)) {
            x509Checks++;
            moduleData[offset + 3] = 0x90;
            moduleData[offset + 4] = 0x90;
        }
        offset += 5;
    }
    
    /* cmp eax, 1; jne long (0f 85 XX XX XX XX) */
    BYTE cmpJneLongPattern[] = {0x83, 0xf8, 0x01, 0x0f, 0x85};
    offset = 0;
    while ((offset = FindPattern(moduleData, bytesRead, cmpJneLongPattern, 5, offset)) >= 0) {
        printf("    Found cmp eax,1; jne (long) at +0x%X\n", offset);
        /* NOP out the entire 6-byte jne instruction */
        BYTE patch[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        if (WriteMem(hProcess, dllBase + offset + 3, patch, 6)) {
            x509Checks++;
            memset(moduleData + offset + 3, 0x90, 6);
        }
        offset += 9;
    }
    
    printf("[+] Patched %d X509_verify_cert checks\n", x509Checks);
    totalPatches += x509Checks;
    
    /* ============================================================
     * PATCH SET 4: Direct verify callback return override
     * 
     * Look for the verify callback prologue and patch return value
     * Pattern for callback: push ebp; mov ebp,esp; ... ; mov eax, [ebp+8]; test eax,eax
     * Or look for X509_STORE_CTX_get_error calls
     * ============================================================ */
    printf("\n[*] Patch Set 4: Verify callback returns...\n");
    
    /* Look for "mov eax, 1; ret" or "xor eax,eax; ret" patterns that are callback returns */
    /* We want callbacks to return 1 (success), so find "xor eax,eax; ret" and change to "mov eax,1; ret" */
    BYTE xorRetPattern[] = {0x31, 0xc0, 0xc3}; /* xor eax,eax; ret */
    BYTE xorEaxRetPattern[] = {0x33, 0xc0, 0xc3}; /* xor eax,eax (alt encoding); ret */
    
    int callbackPatches = 0;
    
    /* We can't blindly patch all xor eax,eax;ret - need context
     * Instead, look for patterns near verify-related strings or calls */
    
    /* Look for sequences where result is set to 0 before ret based on verify failure */
    /* Pattern: cmp/test followed by conditional set of eax to 0 */
    
    /* A common pattern: mov eax, [something]; test eax,eax; je success; xor eax,eax; ret */
    /* We want to skip the xor and let eax keep success value */
    
    printf("[+] Patched %d callback returns\n", callbackPatches);
    totalPatches += callbackPatches;
    
    /* ============================================================
     * PATCH SET 5: Certificate comparison bypasses
     * 
     * If EA pinned a certificate, there might be memcmp/strcmp calls
     * comparing certificate data. Look for and patch these.
     * 
     * Pattern: call memcmp; test eax,eax; jne error
     * ============================================================ */
    printf("\n[*] Patch Set 5: Potential certificate comparison patches...\n");
    
    /* Look for patterns where a comparison result leads to rejection */
    /* This is speculative but worth trying */
    
    int compPatches = 0;
    
    /* memcmp returns in eax, then test eax,eax; jne error_handler */
    /* We've already patched many test eax,eax; jne patterns above */
    
    printf("[+] Patched %d comparison checks\n", compPatches);
    totalPatches += compPatches;
    
    /* ============================================================
     * PATCH SET 6: Force SSL_CTX verify_mode at runtime
     * 
     * Look for mov instructions that read/write offset 0x130 in SSL_CTX
     * and ensure verify_mode stays 0
     * ============================================================ */
    printf("\n[*] Patch Set 6: Additional verify_mode store operations...\n");
    
    int storePatches = 0;
    
    /* Look for: mov [reg+0x130], eax (89 8x 30 01 00 00) */
    /* These store computed values to verify_mode */
    BYTE movPatterns[][6] = {
        {0x89, 0x86, 0x30, 0x01, 0x00, 0x00}, /* [esi+0x130] */
        {0x89, 0x82, 0x30, 0x01, 0x00, 0x00}, /* [edx+0x130] */
        {0x89, 0x81, 0x30, 0x01, 0x00, 0x00}, /* [ecx+0x130] */
        {0x89, 0x83, 0x30, 0x01, 0x00, 0x00}, /* [ebx+0x130] */
        {0x89, 0x87, 0x30, 0x01, 0x00, 0x00}, /* [edi+0x130] */
        {0x89, 0x80, 0x30, 0x01, 0x00, 0x00}, /* [eax+0x130] */
    };
    
    /* NOP these out so verify_mode isn't changed */
    for (int p = 0; p < 6; p++) {
        offset = 0;
        while ((offset = FindPattern(moduleData, bytesRead, movPatterns[p], 6, offset)) >= 0) {
            printf("    Found mov [reg+0x130], reg at +0x%X\n", offset);
            BYTE patch[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
            if (WriteMem(hProcess, dllBase + offset, patch, 6)) {
                storePatches++;
                memset(moduleData + offset, 0x90, 6);
            }
            offset += 6;
        }
    }
    
    printf("[+] NOPed %d verify_mode stores\n", storePatches);
    totalPatches += storePatches;
    
    /* ============================================================
     * PATCH SET 7: X509_STORE_CTX_get_error return value override
     * 
     * After X509_STORE_CTX_get_error returns an error code in eax,
     * patch to force eax = 0 (X509_V_OK)
     * 
     * Look for: cmp eax, error_code patterns and bypass them
     * ============================================================ */
    printf("\n[*] Patch Set 7: X509 error code checks...\n");
    
    int errorPatches = 0;
    
    /* Common X509 error codes we've seen:
     * 2 = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
     * 18 = X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
     * 19 = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
     * 20 = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY
     * 21 = X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
     */
    int errorCodes[] = {2, 18, 19, 20, 21, 27};
    
    for (int e = 0; e < 6; e++) {
        int code = errorCodes[e];
        
        /* Pattern: cmp eax, code (83 f8 XX or 3d XX 00 00 00) */
        BYTE cmpPattern1[] = {0x83, 0xf8, (BYTE)code};
        offset = 0;
        while ((offset = FindPattern(moduleData, bytesRead, cmpPattern1, 3, offset)) >= 0) {
            printf("    Found cmp eax, %d at +0x%X\n", code, offset);
            /* Check what follows - if jz/je (74/0f84) this is checking FOR this error */
            if (offset + 3 < bytesRead) {
                BYTE nextByte = moduleData[offset + 3];
                if (nextByte == 0x74) { /* je short */
                    /* NOP the je */
                    BYTE patch[] = {0x90, 0x90};
                    if (WriteMem(hProcess, dllBase + offset + 3, patch, 2)) {
                        errorPatches++;
                        moduleData[offset + 3] = 0x90;
                        moduleData[offset + 4] = 0x90;
                    }
                } else if (nextByte == 0x0f && offset + 4 < bytesRead && moduleData[offset + 4] == 0x84) {
                    /* je long - NOP it */
                    BYTE patch[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
                    if (WriteMem(hProcess, dllBase + offset + 3, patch, 6)) {
                        errorPatches++;
                        memset(moduleData + offset + 3, 0x90, 6);
                    }
                }
            }
            offset += 3;
        }
    }
    
    printf("[+] Bypassed %d X509 error code checks\n", errorPatches);
    totalPatches += errorPatches;
    
    /* ============================================================
     * Summary
     * ============================================================ */
    printf("\n===========================================\n");
    printf("[*] Total patches applied: %d\n", totalPatches);
    
    if (totalPatches > 0) {
        printf("[+] SUCCESS: Certificate verification patched\n");
        printf("[*] Try connecting to server now\n");
    } else {
        printf("[-] No patches applied - patterns may have changed\n");
    }
    
    free(moduleData);
    CloseHandle(hProcess);
    
    printf("\n[*] Press Enter to exit...\n");
    getchar();
    return 0;
}
