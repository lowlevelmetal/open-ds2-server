/*
 * Dead Space 2 SSL Certificate Bypass - Version 8
 * 
 * Uses position-independent pattern matching.
 * 
 * Key patterns to find in the X509 verification callback:
 * 1. The sequence "cmp ebx, 0xb; jne <far>" = 83 fb 0b 0f 85 ?? ?? ?? ??
 * 2. The "or eax, -1" return = 83 c8 ff
 */

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>

// Pattern: cmp ebx, 0xb; jne (6 byte jump)
// This is unique enough in the context of error checking
unsigned char PATTERN_CMP_JNE[] = {
    0x83, 0xfb, 0x0b,    // cmp ebx, 0xb
    0x0f, 0x85           // jne (near jump opcode, followed by 4 byte offset)
};

// We need context before the cmp to make it unique
// Looking at: 83 fb 04 74 09 83 fb 0b 0f 85
// cmp ebx,4; je +9; cmp ebx,0xb; jne ...
unsigned char PATTERN_CONTEXT[] = {
    0x83, 0xfb, 0x04,    // cmp ebx, 0x4
    0x74, 0x09,          // je +9
    0x83, 0xfb, 0x0b,    // cmp ebx, 0xb
    0x0f, 0x85           // jne ...
};

// Pattern for return -1: or eax, 0xffffffff followed by call and ret
unsigned char PATTERN_RETURN_FAIL[] = {
    0x83, 0xc8, 0xff,    // or eax, -1
    0xe8                 // call ...
};

// More context for return: preceded by call to some function
// Looking at: e8 26 fc ff ff 83 c8 ff e8
unsigned char PATTERN_RETURN_CONTEXT[] = {
    0xe8, '?', '?', '?', '?',  // call (some function) - will use wildcards
    0x83, 0xc8, 0xff,          // or eax, -1
    0xe8                        // call (epilogue)
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

// Find pattern with optional wildcards (0xFF means wildcard)
unsigned char* FindPatternWildcard(unsigned char* data, DWORD dataSize, 
                                   unsigned char* pattern, DWORD patternSize,
                                   unsigned char wildcard) {
    for (DWORD i = 0; i <= dataSize - patternSize; i++) {
        BOOL found = TRUE;
        for (DWORD j = 0; j < patternSize; j++) {
            if (pattern[j] != wildcard && data[i + j] != pattern[j]) {
                found = FALSE;
                break;
            }
        }
        if (found) return &data[i];
    }
    return NULL;
}

unsigned char* FindPattern(unsigned char* data, DWORD dataSize, 
                          unsigned char* pattern, DWORD patternSize) {
    return FindPatternWildcard(data, dataSize, pattern, patternSize, 0xFF);
}

// Find all occurrences
int FindAllPatterns(unsigned char* data, DWORD dataSize,
                   unsigned char* pattern, DWORD patternSize,
                   DWORD* offsets, int maxOffsets) {
    int count = 0;
    DWORD searchStart = 0;
    
    while (searchStart < dataSize - patternSize && count < maxOffsets) {
        unsigned char* found = FindPattern(data + searchStart, dataSize - searchStart, 
                                          pattern, patternSize);
        if (found) {
            offsets[count++] = (DWORD)(found - data);
            searchStart = (DWORD)(found - data) + 1;
        } else {
            break;
        }
    }
    return count;
}

int main() {
    printf("=== Dead Space 2 SSL Bypass v8 ===\n");
    printf("Using position-independent pattern matching\n\n");
    
    // Find Dead Space 2 process
    DWORD pid = FindProcessByName("deadspace2.exe");
    if (!pid) {
        printf("[-] Dead Space 2 not running\n");
        printf("    Start the game, wait for main menu, then run this patcher.\n");
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
    
    if (moduleSize < 6000000) {
        printf("[-] Module too small - DLL not unpacked yet. Wait longer.\n");
        CloseHandle(hProcess);
        return 1;
    }
    
    // Read module
    unsigned char* buffer = (unsigned char*)malloc(moduleSize);
    if (!buffer) {
        printf("[-] Failed to allocate memory\n");
        CloseHandle(hProcess);
        return 1;
    }
    
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, (LPVOID)moduleBase, buffer, moduleSize, &bytesRead)) {
        printf("[-] Failed to read memory (error: %lu)\n", GetLastError());
        free(buffer);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Read %lu bytes\n\n", (DWORD)bytesRead);
    
    int patchCount = 0;
    
    // PATCH 1: Find the "cmp ebx,4; je; cmp ebx,0xb; jne" sequence
    printf("[*] Searching for SSL verification pattern...\n");
    
    DWORD offsets[10];
    int found = FindAllPatterns(buffer, moduleSize, PATTERN_CONTEXT, sizeof(PATTERN_CONTEXT), offsets, 10);
    
    printf("[*] Found %d matches for context pattern\n", found);
    
    for (int i = 0; i < found; i++) {
        DWORD offset = offsets[i];
        printf("[*] Match %d at offset 0x%lX\n", i+1, offset);
        
        // The JNE we want to NOP is at offset + 7 (after cmp ebx,4; je +9; cmp ebx,0xb)
        DWORD jneOffset = offset + 7;
        
        // Verify it's a JNE
        if (buffer[jneOffset] == 0x0f && buffer[jneOffset+1] == 0x85) {
            printf("[+] Confirmed JNE at offset 0x%lX\n", jneOffset);
            
            // NOP the 6-byte JNE instruction
            unsigned char nop6[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
            DWORD patchAddr = moduleBase + jneOffset;
            
            DWORD oldProtect;
            if (VirtualProtectEx(hProcess, (LPVOID)patchAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                if (WriteProcessMemory(hProcess, (LPVOID)patchAddr, nop6, 6, NULL)) {
                    printf("[+] PATCH %d: JNE at 0x%08lX -> NOP\n", patchCount+1, patchAddr);
                    patchCount++;
                }
                VirtualProtectEx(hProcess, (LPVOID)patchAddr, 6, oldProtect, &oldProtect);
            }
        }
    }
    
    // PATCH 2: Find and fix ALL "or eax, -1" returns
    printf("\n[*] Searching for return -1 patterns...\n");
    
    found = FindAllPatterns(buffer, moduleSize, PATTERN_RETURN_FAIL, sizeof(PATTERN_RETURN_FAIL), offsets, 10);
    printf("[*] Found %d 'or eax,-1; call' patterns\n", found);
    
    for (int i = 0; i < found; i++) {
        DWORD offset = offsets[i];
        printf("[*] Return fail at offset 0x%lX\n", offset);
        
        // Change "or eax, -1" to "xor eax, eax; inc eax" (return 1 instead of -1)
        unsigned char patch[] = {0x31, 0xc0, 0x40};  // xor eax,eax; inc eax
        DWORD patchAddr = moduleBase + offset;
        
        DWORD oldProtect;
        if (VirtualProtectEx(hProcess, (LPVOID)patchAddr, 3, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            if (WriteProcessMemory(hProcess, (LPVOID)patchAddr, patch, 3, NULL)) {
                printf("[+] PATCH %d: return -1 at 0x%08lX -> return 1\n", patchCount+1, patchAddr);
                patchCount++;
            }
            VirtualProtectEx(hProcess, (LPVOID)patchAddr, 3, oldProtect, &oldProtect);
        }
    }
    
    // PATCH 3: Find depth checks - "cmp esi, 4; je <far>"
    printf("\n[*] Searching for depth check patterns...\n");
    
    unsigned char depthPattern[] = {0x83, 0xfe, 0x04, 0x0f, 0x84};  // cmp esi,4; je ...
    found = FindAllPatterns(buffer, moduleSize, depthPattern, sizeof(depthPattern), offsets, 10);
    printf("[*] Found %d depth==4 checks\n", found);
    
    for (int i = 0; i < found; i++) {
        DWORD offset = offsets[i];
        DWORD jmpOffset = offset + 3;  // Skip cmp, point at je
        
        unsigned char nop6[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        DWORD patchAddr = moduleBase + jmpOffset;
        
        DWORD oldProtect;
        if (VirtualProtectEx(hProcess, (LPVOID)patchAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            if (WriteProcessMemory(hProcess, (LPVOID)patchAddr, nop6, 6, NULL)) {
                printf("[+] PATCH %d: depth check at 0x%08lX -> NOP\n", patchCount+1, patchAddr);
                patchCount++;
            }
            VirtualProtectEx(hProcess, (LPVOID)patchAddr, 6, oldProtect, &oldProtect);
        }
    }
    
    unsigned char depth3Pattern[] = {0x83, 0xfe, 0x03, 0x0f, 0x84};  // cmp esi,3; je ...
    found = FindAllPatterns(buffer, moduleSize, depth3Pattern, sizeof(depth3Pattern), offsets, 10);
    printf("[*] Found %d depth==3 checks\n", found);
    
    for (int i = 0; i < found; i++) {
        DWORD offset = offsets[i];
        DWORD jmpOffset = offset + 3;
        
        unsigned char nop6[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
        DWORD patchAddr = moduleBase + jmpOffset;
        
        DWORD oldProtect;
        if (VirtualProtectEx(hProcess, (LPVOID)patchAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
            if (WriteProcessMemory(hProcess, (LPVOID)patchAddr, nop6, 6, NULL)) {
                printf("[+] PATCH %d: depth check at 0x%08lX -> NOP\n", patchCount+1, patchAddr);
                patchCount++;
            }
            VirtualProtectEx(hProcess, (LPVOID)patchAddr, 6, oldProtect, &oldProtect);
        }
    }
    
    free(buffer);
    CloseHandle(hProcess);
    
    printf("\n========================================\n");
    if (patchCount > 0) {
        printf("[+] Applied %d patches!\n", patchCount);
        printf("[+] SSL verification should now accept all certificates.\n");
        printf("[*] Try connecting to multiplayer.\n");
        return 0;
    } else {
        printf("[-] No patches applied.\n");
        return 1;
    }
}
