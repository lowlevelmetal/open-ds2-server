/*
 * Dead Space 2 SSL Certificate Bypass - Version 7
 * 
 * ANALYSIS OF X509 VERIFICATION CALLBACK:
 * 
 * Function at 0x795e5ac5 handles certificate verification:
 * 
 * The function checks error codes and routes them:
 * - Codes 2, 0x15, 0x16, 6, 0xf -> special handler at 0x5bbf
 * - Codes 8, 4, 0xb -> process at 0x5b2f
 * - All other codes (including 0x12) -> reject at 0x5cd3
 * 
 * At 0x5cd3, it further checks:
 * - Codes 1, 3, 0xd, 0x10, 0x11 -> return -1
 * - Code 0x12 (self-signed) -> falls through to also return -1
 * 
 * SUCCESS PATH is at 0x795e5cc2: mov eax, [ebp-0x1c]; jmp epilogue
 * 
 * PATCH STRATEGY:
 * Change JNE at 0x5b29 to always allow (JMP to success handler)
 * OR change the return -1 to return 1
 */

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>

// Function prologue pattern
unsigned char FUNC_PROLOGUE[] = {
    0x6a, 0x10,                         // push 0x10
    0x68, 0xc8, 0x5e, 0x67, 0x79,       // push 0x79675ec8
    0xe8                                 // call (start of call instruction)
};

// Pattern at 0x795e5b26-0x795e5b2f
unsigned char PATTERN_JNE[] = {
    0x83, 0xfb, 0x0b,                   // cmp ebx, 0xb
    0x0f, 0x85, 0xa4, 0x01, 0x00, 0x00  // jne 0x795e5cd3
};

// Pattern for return failure at 0x795e5cfc
unsigned char PATTERN_RETURN_FAIL[] = {
    0x83, 0xc8, 0xff,                   // or eax, 0xffffffff
    0xe8                                 // call (start of epilogue call)
};

DWORD FindProcessByName(const char* name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    DWORD pid = 0;
    if (Process32First(snapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe));
    }
    
    CloseHandle(snapshot);
    return pid;
}

DWORD FindModule(HANDLE hProcess, const char* moduleName, DWORD* moduleSize) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char szModName[MAX_PATH];
            if (GetModuleFileNameExA(hProcess, hMods[i], szModName, sizeof(szModName))) {
                char* lastSlash = strrchr(szModName, '\\');
                char* name = lastSlash ? lastSlash + 1 : szModName;
                
                if (_stricmp(name, moduleName) == 0) {
                    MODULEINFO modInfo;
                    if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                        *moduleSize = modInfo.SizeOfImage;
                        return (DWORD)hMods[i];
                    }
                }
            }
        }
    }
    return 0;
}

unsigned char* FindPattern(unsigned char* data, DWORD dataSize, unsigned char* pattern, DWORD patternSize) {
    for (DWORD i = 0; i <= dataSize - patternSize; i++) {
        BOOL found = TRUE;
        for (DWORD j = 0; j < patternSize; j++) {
            if (data[i + j] != pattern[j]) {
                found = FALSE;
                break;
            }
        }
        if (found) return &data[i];
    }
    return NULL;
}

int main() {
    printf("=== Dead Space 2 SSL Bypass v7 ===\n");
    printf("Patching X509 verification callback\n\n");
    
    // Find Dead Space 2 process
    DWORD pid = FindProcessByName("deadspace2.exe");
    if (!pid) {
        printf("[-] Dead Space 2 not running\n");
        printf("    Please start the game first, wait until main menu, then run this patcher.\n");
        return 1;
    }
    printf("[+] Found deadspace2.exe (PID: %lu)\n", pid);
    
    // Open process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process (error: %lu)\n", GetLastError());
        return 1;
    }
    printf("[+] Process opened\n");
    
    // Find activation.x86.dll
    DWORD moduleSize = 0;
    DWORD moduleBase = FindModule(hProcess, "activation.x86.dll", &moduleSize);
    if (!moduleBase) {
        printf("[-] activation.x86.dll not found\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] activation.x86.dll at 0x%08lX (size: %lu bytes)\n", moduleBase, moduleSize);
    
    // Check if this is the unpacked size
    if (moduleSize < 6000000) {
        printf("[-] Module size too small (%lu bytes) - DLL may not be unpacked yet\n", moduleSize);
        printf("    Wait longer at the main menu and try again.\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Module size indicates unpacked DLL\n");
    
    // Read module memory
    unsigned char* buffer = (unsigned char*)malloc(moduleSize);
    if (!buffer) {
        printf("[-] Failed to allocate memory\n");
        CloseHandle(hProcess);
        return 1;
    }
    
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPVOID)moduleBase, buffer, moduleSize, &bytesRead)) {
        printf("[-] Failed to read process memory (error: %lu)\n", GetLastError());
        free(buffer);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Read %lu bytes from module\n", (DWORD)bytesRead);
    
    int patchCount = 0;
    
    // PATCH 1: Find function prologue
    printf("\n[*] Looking for X509 callback function prologue...\n");
    unsigned char* funcStart = FindPattern(buffer, moduleSize, FUNC_PROLOGUE, sizeof(FUNC_PROLOGUE));
    if (funcStart) {
        DWORD funcOffset = (DWORD)(funcStart - buffer);
        printf("[+] Found function prologue at offset 0x%lX (addr: 0x%08lX)\n", 
               funcOffset, moduleBase + funcOffset);
        
        // Verify this is our function by checking more context
        // At funcStart + 0x64 should be the JNE instruction
        DWORD jneOffset = funcOffset + 0x61;  // 0x5b26 - 0x5ac5 = 0x61
        
        printf("[*] Checking JNE at offset 0x%lX...\n", jneOffset);
        if (jneOffset + sizeof(PATTERN_JNE) <= moduleSize) {
            if (memcmp(buffer + jneOffset, PATTERN_JNE, sizeof(PATTERN_JNE)) == 0) {
                printf("[+] Found JNE pattern: cmp ebx, 0xb; jne <reject>\n");
                
                // PATCH: Change JNE to JMP to success path
                // We need to calculate new offset to jump to 0x5cc2 instead of 0x5cd3
                // Current: jne 0x795e5cd3 (0f 85 a4 01 00 00) from 0x5b29
                // Target success path at 0x5cc2
                // We want to unconditionally jump to 0x5cc2
                
                // But wait - we need to handle the case properly
                // The best patch is to NOP the JNE so we fall through to 0x5b2f
                // which calls the helper function
                
                // Actually, let's make error 0x12 act like error 0xb by changing cmp ebx,0xb to cmp ebx,0x12
                // No - that would break legitimate 0xb handling
                
                // BETTER: Patch the JNE to always jump to success
                // From 0x795e5b29, we want to jump to 0x795e5cc2
                // Offset = 0x5cc2 - 0x5b29 - 6 = 0x193
                
                // Or SIMPLEST: Just NOP the JNE (6 bytes) so it falls through
                // This makes ALL unknown errors go to the handler at 0x5b2f
                
                unsigned char nop6[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
                DWORD jneAddr = moduleBase + jneOffset + 3;  // +3 to skip cmp instruction, point at jne
                
                printf("[*] Patching JNE at 0x%08lX to NOPs...\n", jneAddr);
                
                DWORD oldProtect;
                if (VirtualProtectEx(hProcess, (LPVOID)jneAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    if (WriteProcessMemory(hProcess, (LPVOID)jneAddr, nop6, 6, NULL)) {
                        printf("[+] PATCH 1 SUCCESS: JNE NOPed\n");
                        patchCount++;
                        VirtualProtectEx(hProcess, (LPVOID)jneAddr, 6, oldProtect, &oldProtect);
                    } else {
                        printf("[-] Failed to write patch (error: %lu)\n", GetLastError());
                    }
                } else {
                    printf("[-] Failed to change memory protection (error: %lu)\n", GetLastError());
                }
            } else {
                printf("[-] JNE pattern not found at expected offset\n");
                printf("    Expected: 83 fb 0b 0f 85 a4 01 00 00\n");
                printf("    Found:    ");
                for (int k = 0; k < 9; k++) printf("%02x ", buffer[jneOffset + k]);
                printf("\n");
            }
        }
    } else {
        printf("[-] Function prologue not found\n");
    }
    
    // PATCH 2: Find and patch the return -1 instruction
    printf("\n[*] Looking for return failure pattern...\n");
    unsigned char* retFail = FindPattern(buffer, moduleSize, PATTERN_RETURN_FAIL, sizeof(PATTERN_RETURN_FAIL));
    if (retFail) {
        DWORD retOffset = (DWORD)(retFail - buffer);
        printf("[+] Found 'or eax, -1' at offset 0x%lX\n", retOffset);
        
        // Verify context - should be near our function
        DWORD expectedOffset = 0x5cfc - 0x5ac5 + (funcStart ? (funcStart - buffer) : 0);
        
        // Change "or eax, -1" (83 c8 ff) to "xor eax, eax; inc eax" (31 c0 40) = return 1
        // Or even simpler: "mov eax, 1" but that's 5 bytes
        // 31 c0 = xor eax, eax (2 bytes)  
        // 40    = inc eax (1 byte)
        // Total = 3 bytes, same as original
        
        unsigned char patch_return1[] = {0x31, 0xc0, 0x40};  // xor eax,eax; inc eax
        DWORD patchAddr = moduleBase + retOffset;
        
        printf("[*] Patching return -1 to return 1 at 0x%08lX...\n", patchAddr);
        
        DWORD oldProtect;
        if (VirtualProtectEx(hProcess, (LPVOID)patchAddr, 3, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            if (WriteProcessMemory(hProcess, (LPVOID)patchAddr, patch_return1, 3, NULL)) {
                printf("[+] PATCH 2 SUCCESS: Return value changed to 1\n");
                patchCount++;
                VirtualProtectEx(hProcess, (LPVOID)patchAddr, 3, oldProtect, &oldProtect);
            } else {
                printf("[-] Failed to write patch (error: %lu)\n", GetLastError());
            }
        } else {
            printf("[-] Failed to change memory protection (error: %lu)\n", GetLastError());
        }
    } else {
        printf("[-] Return failure pattern not found\n");
    }
    
    // PATCH 3: Also patch the early exits for depth checks
    // At 0x5ade and 0x5ae7, there are JE to 0x5cd3 for depth==4 and depth==3
    printf("\n[*] Looking for depth check jumps...\n");
    
    // Pattern: cmp esi, 0x4; je <reject>
    unsigned char depthCheck4[] = {0x83, 0xfe, 0x04, 0x0f, 0x84};
    unsigned char* depth4 = FindPattern(buffer, moduleSize, depthCheck4, sizeof(depthCheck4));
    if (depth4) {
        DWORD offset = (DWORD)(depth4 - buffer);
        printf("[+] Found depth==4 check at offset 0x%lX\n", offset);
        
        // NOP the JE (6 bytes starting at offset+3)
        unsigned char nop6[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        DWORD patchAddr = moduleBase + offset + 3;
        
        DWORD oldProtect;
        if (VirtualProtectEx(hProcess, (LPVOID)patchAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            if (WriteProcessMemory(hProcess, (LPVOID)patchAddr, nop6, 6, NULL)) {
                printf("[+] PATCH 3 SUCCESS: depth==4 check NOPed\n");
                patchCount++;
                VirtualProtectEx(hProcess, (LPVOID)patchAddr, 6, oldProtect, &oldProtect);
            }
        }
    }
    
    // Pattern: cmp esi, 0x3; je <reject>
    unsigned char depthCheck3[] = {0x83, 0xfe, 0x03, 0x0f, 0x84};
    unsigned char* depth3 = FindPattern(buffer, moduleSize, depthCheck3, sizeof(depthCheck3));
    if (depth3) {
        DWORD offset = (DWORD)(depth3 - buffer);
        printf("[+] Found depth==3 check at offset 0x%lX\n", offset);
        
        unsigned char nop6[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        DWORD patchAddr = moduleBase + offset + 3;
        
        DWORD oldProtect;
        if (VirtualProtectEx(hProcess, (LPVOID)patchAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            if (WriteProcessMemory(hProcess, (LPVOID)patchAddr, nop6, 6, NULL)) {
                printf("[+] PATCH 4 SUCCESS: depth==3 check NOPed\n");
                patchCount++;
                VirtualProtectEx(hProcess, (LPVOID)patchAddr, 6, oldProtect, &oldProtect);
            }
        }
    }
    
    free(buffer);
    CloseHandle(hProcess);
    
    printf("\n========================================\n");
    if (patchCount > 0) {
        printf("[+] Applied %d patches successfully!\n", patchCount);
        printf("[+] SSL certificate verification should now be bypassed.\n");
        printf("[*] Try connecting to multiplayer now.\n");
    } else {
        printf("[-] No patches applied. The DLL structure may have changed.\n");
    }
    
    return patchCount > 0 ? 0 : 1;
}
