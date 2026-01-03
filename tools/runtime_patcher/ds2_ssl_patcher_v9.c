/*
 * Dead Space 2 SSL Patcher v9 - Verify Callback Patch
 * 
 * The game has a custom SSL verify callback that rejects our certificate
 * even when verify_mode is set to 0. We need to patch the callback itself
 * to always return 1 (success).
 * 
 * OpenSSL verify callback signature:
 *   int verify_callback(int preverify_ok, X509_STORE_CTX *ctx)
 * 
 * The callback should return 1 to accept, 0 to reject.
 * We need to find the callback and patch it to always return 1.
 * 
 * Strategy:
 * 1. Find SSL_CTX_set_verify calls where a callback is set
 * 2. Find the callback function 
 * 3. Patch the callback to return 1 immediately
 * 
 * Build: i686-w64-mingw32-gcc -o ds2_ssl_patcher_v9.exe ds2_ssl_patcher_v9.c -lpsapi -static -O2
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

int FindPattern(BYTE* data, SIZE_T dataSize, BYTE* pattern, SIZE_T patternSize, SIZE_T startOffset) {
    for (SIZE_T i = startOffset; i < dataSize - patternSize; i++) {
        if (memcmp(data + i, pattern, patternSize) == 0) {
            return (int)i;
        }
    }
    return -1;
}

int main(int argc, char* argv[]) {
    printf("===========================================\n");
    printf(" Dead Space 2 SSL Patcher v9\n");
    printf(" Verify Callback Return Patch\n");
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
     * PATCH 1: verify_mode = 1 -> 0
     * ============================================================ */
    printf("\n[*] Patch 1: SSL_set_verify (verify_mode = 1 -> 0)...\n");
    
    BYTE verifyPatterns[][10] = {
        {0xc7, 0x86, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
        {0xc7, 0x82, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
        {0xc7, 0x81, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
        {0xc7, 0x83, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
        {0xc7, 0x87, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
        {0xc7, 0x80, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
    };
    
    int verifyCount = 0;
    for (int p = 0; p < 6; p++) {
        int offset = 0;
        while ((offset = FindPattern(moduleData, bytesRead, verifyPatterns[p], 10, offset)) >= 0) {
            printf("    Found verify_mode=1 at +0x%X\n", offset);
            BYTE newVal = 0x00;
            if (WriteMem(hProcess, dllBase + offset + 6, &newVal, 1)) {
                verifyCount++;
                moduleData[offset + 6] = 0x00;
            }
            offset += 10;
        }
    }
    printf("[+] Patched %d verify_mode instructions\n", verifyCount);
    totalPatches += verifyCount;
    
    /* ============================================================
     * PATCH 2: Find and patch verify callback functions
     * 
     * A verify callback typically starts with:
     *   push ebp
     *   mov ebp, esp
     *   ... (some code)
     *   xor eax, eax  or  mov eax, 0  (return 0 = reject)
     *   ... or ...
     *   mov eax, 1  (return 1 = accept)
     * 
     * We look for functions that:
     * - Have two parameters (preverify_ok, X509_STORE_CTX*)
     * - Return 0 somewhere (rejection path)
     * - Are referenced from SSL_CTX_set_verify calls
     * 
     * The SSL_CTX_set_verify stores callback at ctx->default_verify_callback
     * which is at offset 0x134 in SSL_CTX.
     * 
     * Look for: mov [reg+0x134], callback_addr
     * Pattern: 89 8x 34 01 00 00 (mov [reg+0x134], ecx/eax/etc)
     * Or: c7 8x 34 01 00 00 XX XX XX XX (mov [reg+0x134], imm32)
     * ============================================================ */
    printf("\n[*] Patch 2: Looking for verify callback setup...\n");
    
    /* Look for mov DWORD PTR [reg+0x134], imm32 - this sets the callback pointer */
    /* c7 86 34 01 00 00 XX XX XX XX = mov [esi+0x134], imm32 */
    BYTE callbackPatterns[][6] = {
        {0xc7, 0x86, 0x34, 0x01, 0x00, 0x00}, /* [esi+0x134] */
        {0xc7, 0x82, 0x34, 0x01, 0x00, 0x00}, /* [edx+0x134] */
        {0xc7, 0x81, 0x34, 0x01, 0x00, 0x00}, /* [ecx+0x134] */
        {0xc7, 0x83, 0x34, 0x01, 0x00, 0x00}, /* [ebx+0x134] */
        {0xc7, 0x87, 0x34, 0x01, 0x00, 0x00}, /* [edi+0x134] */
        {0xc7, 0x80, 0x34, 0x01, 0x00, 0x00}, /* [eax+0x134] */
    };
    
    int callbackCount = 0;
    for (int p = 0; p < 6; p++) {
        int offset = 0;
        while ((offset = FindPattern(moduleData, bytesRead, callbackPatterns[p], 6, offset)) >= 0) {
            /* Get the callback address (next 4 bytes) */
            if (offset + 10 <= bytesRead) {
                DWORD callbackRVA = *(DWORD*)(moduleData + offset + 6);
                /* Convert to offset within module if it's an absolute address */
                DWORD callbackOffset = callbackRVA - (DWORD)(ULONG_PTR)dllBase;
                
                if (callbackOffset < bytesRead && callbackOffset > 0) {
                    printf("    Found callback setup at +0x%X, callback at +0x%X\n", offset, callbackOffset);
                    
                    /* Patch the callback to immediately return 1:
                     * mov eax, 1    ; B8 01 00 00 00
                     * ret           ; C3
                     */
                    BYTE patch[] = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};
                    if (WriteMem(hProcess, dllBase + callbackOffset, patch, 6)) {
                        callbackCount++;
                        printf("    [+] Patched callback to return 1\n");
                    }
                }
            }
            offset += 10;
        }
    }
    
    /* Also look for mov [reg+0x134], reg patterns */
    BYTE callbackRegPatterns[][6] = {
        {0x89, 0x86, 0x34, 0x01, 0x00, 0x00}, /* mov [esi+0x134], eax */
        {0x89, 0x8e, 0x34, 0x01, 0x00, 0x00}, /* mov [esi+0x134], ecx */
        {0x89, 0x96, 0x34, 0x01, 0x00, 0x00}, /* mov [esi+0x134], edx */
    };
    
    for (int p = 0; p < 3; p++) {
        int offset = 0;
        while ((offset = FindPattern(moduleData, bytesRead, callbackRegPatterns[p], 6, offset)) >= 0) {
            printf("    Found callback reg store at +0x%X\n", offset);
            offset += 6;
        }
    }
    
    printf("[+] Patched %d callback functions\n", callbackCount);
    totalPatches += callbackCount;
    
    /* ============================================================
     * PATCH 3: Force SSL_get_verify_result to return 0 (X509_V_OK)
     * 
     * After SSL_connect/SSL_accept, code often checks:
     *   result = SSL_get_verify_result(ssl);
     *   if (result != X509_V_OK) { error... }
     * 
     * SSL_get_verify_result returns ssl->verify_result (offset in SSL struct)
     * We look for where verify_result is read and used in comparisons.
     * 
     * In SSL struct, verify_result is typically around offset 0x104-0x10C
     * Pattern: mov eax, [reg+0x10X]; test eax,eax or cmp eax,0
     * ============================================================ */
    printf("\n[*] Patch 3: Looking for SSL_get_verify_result checks...\n");
    
    /* The verify_result field in OpenSSL 1.0.0 SSL struct is at offset 0x108 */
    /* Look for: mov eax, [reg+0x108] followed by test/cmp */
    BYTE resultPatterns[][6] = {
        {0x8b, 0x86, 0x08, 0x01, 0x00, 0x00}, /* mov eax, [esi+0x108] */
        {0x8b, 0x82, 0x08, 0x01, 0x00, 0x00}, /* mov eax, [edx+0x108] */
        {0x8b, 0x81, 0x08, 0x01, 0x00, 0x00}, /* mov eax, [ecx+0x108] */
        {0x8b, 0x83, 0x08, 0x01, 0x00, 0x00}, /* mov eax, [ebx+0x108] */
        {0x8b, 0x87, 0x08, 0x01, 0x00, 0x00}, /* mov eax, [edi+0x108] */
    };
    
    int resultCount = 0;
    for (int p = 0; p < 5; p++) {
        int offset = 0;
        while ((offset = FindPattern(moduleData, bytesRead, resultPatterns[p], 6, offset)) >= 0) {
            printf("    Found verify_result read at +0x%X\n", offset);
            /* Change to: xor eax, eax (31 c0) followed by NOPs
             * This makes SSL_get_verify_result effectively return 0 */
            BYTE patch[] = {0x31, 0xc0, 0x90, 0x90, 0x90, 0x90};
            if (WriteMem(hProcess, dllBase + offset, patch, 6)) {
                resultCount++;
                memcpy(moduleData + offset, patch, 6);
            }
            offset += 6;
        }
    }
    printf("[+] Patched %d verify_result reads\n", resultCount);
    totalPatches += resultCount;
    
    /* ============================================================
     * PATCH 4: Patch any direct certificate hash/comparison checks
     * 
     * EA might have hardcoded their certificate hash.
     * Look for memcmp-style comparisons near certificate-related code.
     * ============================================================ */
    printf("\n[*] Patch 4: Additional certificate checks...\n");
    
    /* Look for function prologues near the verify_mode setters
     * and patch any "return 0" to "return 1" */
    
    /* Find "xor eax, eax; ret" (31 c0 c3) and nearby patterns
     * that might be in certificate validation functions */
    
    /* This is tricky without more context. Let's try a different approach:
     * Look for the string "verify" or certificate-related error messages */
    
    printf("[+] Skipping advanced certificate checks for now\n");
    
    /* ============================================================
     * Summary
     * ============================================================ */
    printf("\n===========================================\n");
    printf("[*] Total patches applied: %d\n", totalPatches);
    
    if (totalPatches > 0) {
        printf("[+] SUCCESS: SSL verification patched\n");
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
