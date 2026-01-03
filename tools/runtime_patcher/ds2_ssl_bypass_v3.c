/*
 * Dead Space 2 Complete SSL Bypass Patcher v3
 * 
 * Based on COMPREHENSIVE DISASSEMBLY ANALYSIS:
 * 
 * Found the ACTUAL X509 verification callback at 0x795e5ac5
 * It checks error codes and only accepts: 0x02, 0x15, 0x16, 0x06, 0x0f, 0x08, 0x04, 0x0b
 * 
 * Self-signed error 0x12 (18) is NOT in the list and causes rejection!
 * 
 * THE KEY PATCH:
 * At offset 0x4b29 (file offset 0x4f29):
 * Original: 0F 85 A4 01 00 00  (JNE 0x795e5cd3 - jump to fail)
 * Patched:  90 90 90 90 90 90  (6 NOPs - fall through to accept)
 * 
 * This makes the function accept ALL X509 error codes, including self-signed.
 */

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>

DWORD FindProcessByName(const char* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    
    if (Process32First(snapshot, &pe32)) {
        do {
            char lowerName[MAX_PATH];
            strncpy(lowerName, pe32.szExeFile, MAX_PATH);
            for (int i = 0; lowerName[i]; i++) {
                if (lowerName[i] >= 'A' && lowerName[i] <= 'Z')
                    lowerName[i] += 32;
            }
            
            if (strstr(lowerName, processName) != NULL) {
                CloseHandle(snapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe32));
    }
    
    CloseHandle(snapshot);
    return 0;
}

HMODULE FindActivationModule(HANDLE hProcess) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    char moduleName[MAX_PATH];
    
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            if (GetModuleBaseNameA(hProcess, hMods[i], moduleName, sizeof(moduleName))) {
                for (int j = 0; moduleName[j]; j++) {
                    if (moduleName[j] >= 'A' && moduleName[j] <= 'Z')
                        moduleName[j] += 32;
                }
                
                if (strstr(moduleName, "activation") != NULL) {
                    printf("[+] Found module: %s at 0x%p\n", moduleName, hMods[i]);
                    return hMods[i];
                }
            }
        }
    }
    return NULL;
}

int PatchBytes(HANDLE hProcess, void* addr, void* newBytes, int len, const char* desc) {
    DWORD oldProtect;
    SIZE_T written;
    
    if (!VirtualProtectEx(hProcess, addr, len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("    [-] VirtualProtect failed at %p: %lu\n", addr, GetLastError());
        return 0;
    }
    
    if (!WriteProcessMemory(hProcess, addr, newBytes, len, &written)) {
        printf("    [-] WriteProcessMemory failed at %p: %lu\n", addr, GetLastError());
        VirtualProtectEx(hProcess, addr, len, oldProtect, &oldProtect);
        return 0;
    }
    
    FlushInstructionCache(hProcess, addr, len);
    VirtualProtectEx(hProcess, addr, len, oldProtect, &oldProtect);
    
    printf("    [+] Patched at %p: %s\n", addr, desc);
    return 1;
}

/*
 * Search for a byte pattern in process memory
 */
unsigned char* FindPattern(HANDLE hProcess, unsigned char* base, SIZE_T size, 
                           unsigned char* pattern, int patternLen) {
    unsigned char* buffer = malloc(size);
    if (!buffer) return NULL;
    
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, base, buffer, size, &read)) {
        free(buffer);
        return NULL;
    }
    
    for (SIZE_T i = 0; i < read - patternLen; i++) {
        if (memcmp(buffer + i, pattern, patternLen) == 0) {
            free(buffer);
            return base + i;
        }
    }
    
    free(buffer);
    return NULL;
}

int main() {
    printf("=== Dead Space 2 SSL Bypass Patcher v3 ===\n");
    printf("Based on comprehensive disassembly analysis\n\n");
    
    // Find the game process
    DWORD pid = FindProcessByName("deadspace2");
    if (!pid) {
        printf("[-] Dead Space 2 not running! Start the game first.\n");
        printf("    (Looking for process containing 'deadspace2')\n");
        return 1;
    }
    printf("[+] Found Dead Space 2 process: PID %lu\n", pid);
    
    // Open process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process: %lu\n", GetLastError());
        return 1;
    }
    
    // Find activation.x86.dll
    HMODULE hModule = FindActivationModule(hProcess);
    if (!hModule) {
        printf("[-] Could not find activation module. Is the game fully loaded?\n");
        CloseHandle(hProcess);
        return 1;
    }
    
    unsigned char* base = (unsigned char*)hModule;
    
    // Get module size
    MODULEINFO modInfo;
    if (!GetModuleInformation(hProcess, hModule, &modInfo, sizeof(modInfo))) {
        printf("[-] Could not get module info\n");
        CloseHandle(hProcess);
        return 1;
    }
    
    printf("[*] Module base: 0x%p, size: 0x%lx\n", base, modInfo.SizeOfImage);
    
    int total_patches = 0;
    int successful_patches = 0;
    
    // ========================================
    // PATCH 1: THE KEY X509 CALLBACK PATCH
    // ========================================
    printf("\n[*] Patch 1: X509 Verification Callback (THE KEY FIX)\n");
    printf("    This patch makes the game accept self-signed certificates\n");
    
    // The pattern is: 0F 85 A4 01 00 00 (JNE to fail path)
    // After the sequence: 83 FB 0B (cmp ebx, 0xb)
    // Full context pattern for safety
    unsigned char x509_pattern[] = {
        0x83, 0xFB, 0x0B,                    // cmp ebx, 0xb
        0x0F, 0x85, 0xA4, 0x01, 0x00, 0x00   // jne 0x795e5cd3
    };
    
    unsigned char* found = FindPattern(hProcess, base, modInfo.SizeOfImage, 
                                       x509_pattern, sizeof(x509_pattern));
    
    if (found) {
        printf("    [+] Found X509 callback pattern at %p\n", found);
        
        // Patch the JNE to NOPs (at offset +3 from pattern start)
        unsigned char nops[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        unsigned char* jne_addr = found + 3;
        
        total_patches++;
        if (PatchBytes(hProcess, jne_addr, nops, 6, "JNE -> NOPs (accept all errors)")) {
            successful_patches++;
        }
    } else {
        printf("    [!] Pattern not found - trying alternate search...\n");
        
        // Try searching for just the JNE pattern
        unsigned char jne_pattern[] = {0x0F, 0x85, 0xA4, 0x01, 0x00, 0x00};
        
        // Search entire module for this
        unsigned char* buf = malloc(modInfo.SizeOfImage);
        SIZE_T read;
        if (ReadProcessMemory(hProcess, base, buf, modInfo.SizeOfImage, &read)) {
            int found_count = 0;
            for (SIZE_T i = 0; i < read - 6; i++) {
                if (memcmp(buf + i, jne_pattern, 6) == 0) {
                    printf("    Found JNE pattern at offset 0x%zx (addr %p)\n", 
                           i, base + i);
                    found_count++;
                    
                    // Check context - should have cmp ebx, 0xb before it
                    if (i >= 3 && buf[i-3] == 0x83 && buf[i-2] == 0xFB && buf[i-1] == 0x0B) {
                        printf("    [+] Context matches! This is the target.\n");
                        
                        unsigned char nops[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
                        total_patches++;
                        if (PatchBytes(hProcess, base + i, nops, 6, "JNE -> NOPs")) {
                            successful_patches++;
                        }
                    }
                }
            }
            printf("    Total JNE patterns found: %d\n", found_count);
        }
        free(buf);
    }
    
    // ========================================
    // PATCH 2: verify_mode=1 CODE patches
    // ========================================
    printf("\n[*] Patch 2: verify_mode=1 code locations\n");
    
    // Pattern: C7 8x 30 01 00 00 01 00 00 00 (mov dword [reg+0x130], 1)
    // We search for all variants
    
    unsigned char* buf = malloc(modInfo.SizeOfImage);
    SIZE_T read;
    if (ReadProcessMemory(hProcess, base, buf, modInfo.SizeOfImage, &read)) {
        for (SIZE_T i = 0; i < read - 10; i++) {
            // Check for C7 8x 30 01 00 00 01 00 00 00
            if (buf[i] == 0xC7 && 
                (buf[i+1] >= 0x80 && buf[i+1] <= 0x87) &&
                buf[i+2] == 0x30 && buf[i+3] == 0x01 && buf[i+4] == 0x00 && buf[i+5] == 0x00 &&
                buf[i+6] == 0x01 && buf[i+7] == 0x00 && buf[i+8] == 0x00 && buf[i+9] == 0x00) {
                
                printf("    Found verify_mode=1 at offset 0x%zx\n", i);
                
                // Patch: change the immediate 1 to 0
                unsigned char patch[] = {0x00, 0x00, 0x00, 0x00}; // change to 0
                total_patches++;
                if (PatchBytes(hProcess, base + i + 6, patch, 4, "verify_mode=1 -> 0")) {
                    successful_patches++;
                }
            }
        }
    }
    free(buf);
    
    // ========================================
    // PATCH 3: SSL_CTX data structures
    // ========================================
    printf("\n[*] Patch 3: Existing SSL_CTX structures\n");
    
    buf = malloc(modInfo.SizeOfImage);
    if (ReadProcessMemory(hProcess, base, buf, modInfo.SizeOfImage, &read)) {
        int ctx_count = 0;
        
        for (SIZE_T i = 0; i < read - 0x200; i += 4) {
            DWORD* verify_mode = (DWORD*)(buf + i + 0x130);
            
            if (*verify_mode == 1) {
                // Additional validation
                DWORD method_ptr = *(DWORD*)(buf + i);
                
                if (method_ptr >= 0x10000 && method_ptr < 0x80000000) {
                    ctx_count++;
                    
                    // Patch verify_mode to 0
                    DWORD zero = 0;
                    PatchBytes(hProcess, base + i + 0x130, &zero, 4, "SSL_CTX verify_mode -> 0");
                }
            }
        }
        
        printf("    Found and patched %d potential SSL_CTX structures\n", ctx_count);
    }
    free(buf);
    
    // Summary
    printf("\n=== PATCH SUMMARY ===\n");
    printf("Critical patches applied: %d/%d\n", successful_patches, total_patches);
    
    if (successful_patches > 0) {
        printf("\n[+] SUCCESS! SSL certificate verification should now be bypassed.\n");
        printf("[*] The game should now accept self-signed server certificates.\n");
    } else {
        printf("\n[-] No patches were applied. The DLL may not be unpacked yet.\n");
        printf("    Try waiting for the game to fully load before running this.\n");
    }
    
    CloseHandle(hProcess);
    return 0;
}
