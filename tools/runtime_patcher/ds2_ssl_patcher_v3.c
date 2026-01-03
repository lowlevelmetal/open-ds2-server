/*
 * Dead Space 2 SSL Patcher v3 - X509 Verification Bypass
 * 
 * This version patches the actual X509 verification functions that are called
 * during the SSL handshake, not just the setup functions.
 * 
 * Build: i686-w64-mingw32-gcc -o ds2_ssl_patcher_v3.exe ds2_ssl_patcher_v3.c -lpsapi -static
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
    
    return result && written == size;
}

BYTE* FindPattern(BYTE* data, SIZE_T dataSize, const BYTE* pattern, const char* mask, SIZE_T patLen) {
    for (SIZE_T i = 0; i < dataSize - patLen; i++) {
        BOOL found = TRUE;
        for (SIZE_T j = 0; j < patLen; j++) {
            if (mask[j] == 'x' && data[i + j] != pattern[j]) {
                found = FALSE;
                break;
            }
        }
        if (found) return data + i;
    }
    return NULL;
}

BYTE* FindString(BYTE* data, SIZE_T dataSize, const char* str, SIZE_T* offset) {
    SIZE_T strLen = strlen(str);
    for (SIZE_T i = 0; i < dataSize - strLen; i++) {
        if (memcmp(data + i, str, strLen) == 0) {
            *offset = i;
            return data + i;
        }
    }
    return NULL;
}

int PatchSSLVerification(HANDLE hProcess, BYTE* dllBase, DWORD moduleSize) {
    printf("[*] Reading module memory (%lu bytes)...\n", moduleSize);
    
    BYTE* moduleData = (BYTE*)malloc(moduleSize);
    if (!moduleData) {
        printf("[-] Memory allocation failed\n");
        return 0;
    }
    
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, dllBase, moduleData, moduleSize, &read)) {
        printf("[-] Failed to read module memory\n");
        free(moduleData);
        return 0;
    }
    
    int patchCount = 0;
    
    // Strategy 1: Find X509_verify_cert and patch its return
    // Look for the string "X509_verify_cert" which is used in error messages
    printf("\n[*] Looking for X509 verification functions...\n");
    
    SIZE_T strOffset;
    if (FindString(moduleData, read, "X509_verify_cert", &strOffset)) {
        printf("[+] Found 'X509_verify_cert' string at offset 0x%zX\n", strOffset);
    }
    
    // Strategy 2: Find the verify callback being called and patch the result check
    // After SSL_CTX_set_verify, during handshake, OpenSSL calls:
    //   ret = ctx->verify_callback(ok, ctx);
    //   if (!ret) goto fail;
    //
    // We look for: test eax, eax / jz or je (fail path)
    // And NOP out the conditional jump
    
    printf("\n[*] Looking for verification result checks (test eax,eax; jz/je)...\n");
    
    int checkPatches = 0;
    for (SIZE_T i = 0; i < read - 10; i++) {
        // Pattern: test eax, eax (85 C0) followed by jz/je (74 XX or 0F 84 XX XX XX XX)
        if (moduleData[i] == 0x85 && moduleData[i+1] == 0xC0) {
            // Check for short jz (74 XX)
            if (moduleData[i+2] == 0x74) {
                // This is: test eax, eax; jz short
                // Only patch if this looks like it's checking a verification result
                // Heuristic: check if there's a call instruction shortly before
                BOOL hasCallBefore = FALSE;
                for (int k = 1; k < 10; k++) {
                    if (i >= k && moduleData[i-k] == 0xE8) {
                        hasCallBefore = TRUE;
                        break;
                    }
                }
                
                if (hasCallBefore && checkPatches < 50) {
                    // NOP out the jz instruction (74 XX -> 90 90)
                    BYTE nops[2] = {0x90, 0x90};
                    if (WriteMem(hProcess, dllBase + i + 2, nops, 2)) {
                        checkPatches++;
                    }
                }
            }
            // Check for near jz (0F 84 XX XX XX XX)
            else if (moduleData[i+2] == 0x0F && moduleData[i+3] == 0x84) {
                BOOL hasCallBefore = FALSE;
                for (int k = 1; k < 10; k++) {
                    if (i >= k && moduleData[i-k] == 0xE8) {
                        hasCallBefore = TRUE;
                        break;
                    }
                }
                
                if (hasCallBefore && checkPatches < 50) {
                    // NOP out the near jz (6 bytes)
                    BYTE nops[6] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
                    if (WriteMem(hProcess, dllBase + i + 2, nops, 6)) {
                        checkPatches++;
                    }
                }
            }
        }
    }
    printf("[+] Patched %d verification result checks\n", checkPatches);
    patchCount += checkPatches;
    
    // Strategy 3: Find and patch the SSL_CTX verify_mode field directly
    // In OpenSSL 1.0.0, SSL_CTX structure has verify_mode at a specific offset
    // We scan for SSL_CTX structures and zero out the verify_mode
    
    printf("\n[*] Looking for SSL_CTX structures to patch verify_mode...\n");
    
    // SSL_CTX structures often have recognizable patterns
    // They contain method pointers, and verify_mode is typically at offset 0x50-0x60
    // This is very version-specific, so we use heuristics
    
    // Strategy 4: Patch the internal verify callback wrapper
    // Look for function prologues near verification-related strings
    
    printf("\n[*] Looking for verify callback functions to patch...\n");
    
    // Find small functions that return 0 (failed verification)
    // Pattern: push ebp; mov ebp, esp; ... xor eax, eax; ... pop ebp; ret
    int callbackPatches = 0;
    
    for (SIZE_T i = 0; i < read - 20; i++) {
        // Look for function start: push ebp (55), mov ebp, esp (8B EC or 89 E5)
        if (moduleData[i] == 0x55 && 
            ((moduleData[i+1] == 0x8B && moduleData[i+2] == 0xEC) ||
             (moduleData[i+1] == 0x89 && moduleData[i+2] == 0xE5))) {
            
            // Look for xor eax, eax (33 C0 or 31 C0) within next 50 bytes
            for (SIZE_T j = i + 3; j < i + 50 && j < read - 5; j++) {
                if ((moduleData[j] == 0x33 && moduleData[j+1] == 0xC0) ||
                    (moduleData[j] == 0x31 && moduleData[j+1] == 0xC0)) {
                    
                    // Check if ret (C3) or leave;ret (C9 C3) follows within 10 bytes
                    for (SIZE_T k = j + 2; k < j + 12 && k < read; k++) {
                        if (moduleData[k] == 0xC3 || 
                            (moduleData[k] == 0xC9 && k + 1 < read && moduleData[k+1] == 0xC3)) {
                            
                            // This is a small function returning 0
                            // Check if it's likely a verify callback (has 2 args typically)
                            // For now, just count - we'll be more selective
                            
                            // Only patch functions that are very small (likely callbacks)
                            SIZE_T funcSize = k - i;
                            if (funcSize < 30 && callbackPatches < 20) {
                                // Change xor eax,eax to mov eax, 1 (B8 01 00 00 00)
                                // But that's 5 bytes vs 2, so use: xor eax,eax; inc eax (33 C0 40)
                                // Or just: push 1; pop eax (6A 01 58) - 3 bytes
                                // Simplest: leave xor eax,eax but add inc eax after
                                // Actually easiest: change 33 C0 to B0 01 (mov al, 1) - works if high bytes already 0
                                
                                // For safety, let's write: 31 C0 40 (xor eax,eax; inc eax) 
                                // This is 3 bytes, same as original 2 + 1 NOP
                                BYTE patchData[3] = {0x31, 0xC0, 0x40};  // xor eax,eax; inc eax
                                
                                // Check if there's room (need at least 1 more byte after)
                                if (j + 3 <= read && moduleData[j+2] != 0xC3) {
                                    if (WriteMem(hProcess, dllBase + j, patchData, 3)) {
                                        callbackPatches++;
                                    }
                                }
                            }
                            break;
                        }
                    }
                    break;
                }
            }
        }
    }
    printf("[+] Patched %d small return-0 functions to return 1\n", callbackPatches);
    patchCount += callbackPatches;
    
    // Strategy 5: Find SSL_get_verify_result and patch callers to ignore result
    printf("\n[*] Looking for SSL_get_verify_result patterns...\n");
    
    // After SSL_get_verify_result, code typically does:
    //   cmp eax, X509_V_OK (0)
    //   jne error
    // We can patch the cmp to always compare 0 with 0
    
    int verifyResultPatches = 0;
    for (SIZE_T i = 0; i < read - 10; i++) {
        // Pattern: cmp eax, 0 (83 F8 00 or 3D 00 00 00 00)
        if ((moduleData[i] == 0x83 && moduleData[i+1] == 0xF8 && moduleData[i+2] == 0x00) ||
            (moduleData[i] == 0x3D && moduleData[i+1] == 0x00 && moduleData[i+2] == 0x00 && 
             moduleData[i+3] == 0x00 && moduleData[i+4] == 0x00)) {
            
            // Check if followed by jne/jnz (75 XX or 0F 85)
            SIZE_T cmpLen = (moduleData[i] == 0x83) ? 3 : 5;
            
            if (moduleData[i + cmpLen] == 0x75 || 
                (moduleData[i + cmpLen] == 0x0F && moduleData[i + cmpLen + 1] == 0x85)) {
                
                // Check if there's a call before this (likely SSL_get_verify_result)
                BOOL hasCallBefore = FALSE;
                for (int k = 1; k < 15; k++) {
                    if (i >= k && moduleData[i-k] == 0xE8) {
                        hasCallBefore = TRUE;
                        break;
                    }
                }
                
                if (hasCallBefore && verifyResultPatches < 30) {
                    // NOP out the conditional jump
                    if (moduleData[i + cmpLen] == 0x75) {
                        BYTE nops[2] = {0x90, 0x90};
                        if (WriteMem(hProcess, dllBase + i + cmpLen, nops, 2)) {
                            verifyResultPatches++;
                        }
                    } else {
                        BYTE nops[6] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
                        if (WriteMem(hProcess, dllBase + i + cmpLen, nops, 6)) {
                            verifyResultPatches++;
                        }
                    }
                }
            }
        }
    }
    printf("[+] Patched %d verify result checks\n", verifyResultPatches);
    patchCount += verifyResultPatches;
    
    // Strategy 6: THE KEY INSIGHT
    // We need to patch SSL_CTX->verify_mode in already-created SSL_CTX structures!
    // Scan memory for potential SSL_CTX structures and patch their verify_mode
    
    printf("\n[*] Scanning for existing SSL_CTX structures...\n");
    
    // In OpenSSL 1.0.0, SSL_CTX has:
    // - method pointer at offset 0
    // - verify_mode (int) at offset ~0x50
    // - verify_callback at offset ~0x54
    // The verify_mode values are: 0=NONE, 1=PEER, 2=FAIL_IF_NO_PEER, 3=CLIENT_ONCE
    
    // Look for dwords that look like verify_mode (1, 2, or 3) followed by 
    // what could be a function pointer
    
    int ctxPatches = 0;
    for (SIZE_T i = 0; i < read - 8; i += 4) {  // Align to 4 bytes
        DWORD val = *(DWORD*)(moduleData + i);
        
        // Check if this could be verify_mode (1, 2, or 3)
        if (val >= 1 && val <= 3) {
            // Check if next dword looks like a function pointer in the module
            DWORD nextVal = *(DWORD*)(moduleData + i + 4);
            
            if (nextVal >= (DWORD)dllBase && nextVal < (DWORD)dllBase + moduleSize) {
                // This might be verify_mode followed by verify_callback
                // Additional check: see if previous values look like pointers too
                // (SSL_CTX has many function pointers before verify_mode)
                
                if (i >= 8) {
                    DWORD prevVal = *(DWORD*)(moduleData + i - 4);
                    if (prevVal >= (DWORD)dllBase && prevVal < (DWORD)dllBase + moduleSize) {
                        // Looks like SSL_CTX structure - patch verify_mode to 0
                        DWORD zero = 0;
                        if (WriteMem(hProcess, dllBase + i, &zero, 4)) {
                            printf("[+] Patched potential SSL_CTX->verify_mode at 0x%zX (was %lu)\n", 
                                   i, val);
                            ctxPatches++;
                        }
                    }
                }
            }
        }
    }
    printf("[+] Patched %d potential SSL_CTX structures\n", ctxPatches);
    patchCount += ctxPatches;
    
    free(moduleData);
    return patchCount;
}

int main(int argc, char* argv[]) {
    printf("==============================================\n");
    printf("  Dead Space 2 SSL Patcher v3 - X509 Bypass\n");
    printf("==============================================\n\n");
    
    int delayMs = 2000;  // Shorter delay - patch sooner
    if (argc > 1) {
        delayMs = atoi(argv[1]);
    }
    
    printf("[*] Looking for %s...\n", GAME_EXE);
    
    DWORD pid = FindProcess(GAME_EXE);
    if (!pid) {
        printf("[!] Game not running. Waiting up to 5 minutes...\n");
        for (int i = 0; i < 300; i++) {
            Sleep(1000);
            pid = FindProcess(GAME_EXE);
            if (pid) break;
            if (i % 10 == 0) printf(".");
        }
        printf("\n");
        
        if (!pid) {
            printf("[-] Timeout waiting for game\n");
            return 1;
        }
    }
    
    printf("[+] Found game process: PID %lu\n", pid);
    
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    
    if (!hProcess) {
        printf("[-] Failed to open process: %lu\n", GetLastError());
        return 1;
    }
    
    printf("[*] Waiting for %s to load...\n", TARGET_DLL);
    
    BYTE* dllBase = NULL;
    DWORD moduleSize = 0;
    for (int i = 0; i < 30; i++) {
        dllBase = FindModuleBase(hProcess, TARGET_DLL, &moduleSize);
        if (dllBase) break;
        Sleep(1000);
    }
    
    if (!dllBase) {
        printf("[-] Failed to find %s\n", TARGET_DLL);
        CloseHandle(hProcess);
        return 1;
    }
    
    printf("[+] Found %s at 0x%p (size: %lu)\n", TARGET_DLL, dllBase, moduleSize);
    
    printf("[*] Waiting %d ms for DLL unpacking...\n", delayMs);
    Sleep(delayMs);
    
    printf("\n[*] Applying patches...\n");
    int patches = PatchSSLVerification(hProcess, dllBase, moduleSize);
    
    printf("\n========================================\n");
    printf("[+] Total patches applied: %d\n", patches);
    printf("========================================\n");
    
    CloseHandle(hProcess);
    
    printf("\nPress Enter to exit...");
    getchar();
    
    return 0;
}
