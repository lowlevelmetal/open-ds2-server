/*
 * Dead Space 2 Complete SSL Bypass Patcher v2
 * 
 * This version patches:
 * 1. CODE: Instructions that set verify_mode=1 (for future SSL contexts)
 * 2. DATA: Existing SSL_CTX structures that already have verify_mode=1
 * 3. CODE: X509 verification callback to accept all errors
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
        printf("    [-] VirtualProtect failed: %lu\n", GetLastError());
        return 0;
    }
    
    if (!WriteProcessMemory(hProcess, addr, newBytes, len, &written)) {
        printf("    [-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualProtectEx(hProcess, addr, len, oldProtect, &oldProtect);
        return 0;
    }
    
    FlushInstructionCache(hProcess, addr, len);
    VirtualProtectEx(hProcess, addr, len, oldProtect, &oldProtect);
    
    printf("    [+] Patched: %s\n", desc);
    return 1;
}

int PatchVerifyModeCode(HANDLE hProcess, unsigned char* base) {
    int count = 0;
    
    // Pattern: C7 8x 30 01 00 00 01 00 00 00 (mov dword [reg+0x130], 1)
    // Patch to: C7 8x 30 01 00 00 00 00 00 00 (mov dword [reg+0x130], 0)
    
    struct {
        DWORD offset;
        unsigned char pattern[10];
        unsigned char patch[10];
    } patches[] = {
        {0xB1FF, {0xC7,0x86,0x30,0x01,0x00,0x00,0x01,0x00,0x00,0x00}, 
                 {0xC7,0x86,0x30,0x01,0x00,0x00,0x00,0x00,0x00,0x00}},
        {0xB6FC, {0xC7,0x82,0x30,0x01,0x00,0x00,0x01,0x00,0x00,0x00},
                 {0xC7,0x82,0x30,0x01,0x00,0x00,0x00,0x00,0x00,0x00}},
        {0xCB08, {0xC7,0x83,0x30,0x01,0x00,0x00,0x01,0x00,0x00,0x00},
                 {0xC7,0x83,0x30,0x01,0x00,0x00,0x00,0x00,0x00,0x00}},
    };
    
    printf("\n[*] Patching verify_mode CODE locations...\n");
    
    for (int i = 0; i < 3; i++) {
        unsigned char* addr = base + patches[i].offset;
        unsigned char current[10];
        SIZE_T read;
        
        if (!ReadProcessMemory(hProcess, addr, current, 10, &read)) continue;
        
        if (memcmp(current, patches[i].pattern, 10) == 0) {
            if (PatchBytes(hProcess, addr, patches[i].patch, 10, "verify_mode=1 -> 0")) {
                count++;
            }
        } else if (memcmp(current, patches[i].patch, 10) == 0) {
            printf("    [=] Already patched at 0x%lX\n", patches[i].offset);
            count++;
        }
    }
    
    return count;
}

int PatchX509Callback(HANDLE hProcess, unsigned char* base) {
    printf("\n[*] Patching X509 verification callback...\n");
    
    unsigned char* addr = base + 0x4F29;
    unsigned char original[] = {0x0F, 0x85, 0xA4, 0x01, 0x00, 0x00};  // JNZ
    unsigned char patched[] = {0xE9, 0x90, 0x00, 0x00, 0x00, 0x90};   // JMP + NOP
    
    unsigned char current[6];
    SIZE_T read;
    
    if (!ReadProcessMemory(hProcess, addr, current, 6, &read)) {
        printf("    [-] Read failed\n");
        return 0;
    }
    
    if (memcmp(current, original, 6) == 0) {
        return PatchBytes(hProcess, addr, patched, 6, "JNZ -> JMP (accept all errors)");
    } else if (memcmp(current, patched, 6) == 0) {
        printf("    [=] Already patched\n");
        return 1;
    }
    
    printf("    [!] Unexpected bytes at callback location\n");
    return 0;
}

int PatchVerifyModeData(HANDLE hProcess, unsigned char* base, SIZE_T size) {
    printf("\n[*] Scanning for existing SSL_CTX structures with verify_mode=1...\n");
    
    // Read entire module
    unsigned char* buffer = malloc(size);
    if (!buffer) return 0;
    
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, base, buffer, size, &read)) {
        free(buffer);
        return 0;
    }
    
    int count = 0;
    
    // Search for SSL_CTX structures
    // They have verify_mode at +0x130, and we look for value 1
    // We also verify it looks like a valid SSL_CTX by checking nearby fields
    
    for (SIZE_T i = 0; i < read - 0x200; i += 4) {
        // Check if this could be SSL_CTX with verify_mode=1
        DWORD verify_mode = *(DWORD*)(buffer + i + 0x130);
        
        if (verify_mode == 1) {
            // Additional validation: check method pointer at +0x0
            DWORD method_ptr = *(DWORD*)(buffer + i);
            
            // Method pointer should be in a valid range
            if (method_ptr >= 0x10000 && method_ptr < 0x80000000) {
                // Check verify_callback at +0x134 (usually 0 or a function pointer)
                DWORD verify_callback = *(DWORD*)(buffer + i + 0x134);
                
                // Looks like a valid SSL_CTX
                unsigned char* ctx_addr = base + i;
                unsigned char* vm_addr = ctx_addr + 0x130;
                
                printf("    Found SSL_CTX at 0x%p, verify_mode at 0x%p\n", ctx_addr, vm_addr);
                
                DWORD zero = 0;
                if (PatchBytes(hProcess, vm_addr, &zero, 4, "verify_mode=1 -> 0 (data)")) {
                    count++;
                }
                
                // Also set verify_callback to NULL if it's set
                if (verify_callback != 0) {
                    DWORD null_cb = 0;
                    PatchBytes(hProcess, ctx_addr + 0x134, &null_cb, 4, "verify_callback -> NULL");
                }
            }
        }
    }
    
    free(buffer);
    
    if (count == 0) {
        printf("    No SSL_CTX structures found (may not be created yet)\n");
    }
    
    return count;
}

int main(int argc, char* argv[]) {
    printf("====================================================\n");
    printf("  Dead Space 2 SSL Bypass Patcher v2\n");
    printf("====================================================\n\n");
    
    DWORD pid = FindProcessByName("deadspace2");
    if (pid == 0) pid = FindProcessByName("ds2");
    
    if (pid == 0) {
        printf("[-] Dead Space 2 not running!\n");
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    
    printf("[+] Found process: PID %lu\n", pid);
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process (run as admin)\n");
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    
    printf("[*] Waiting 3 seconds for DLL to load...\n");
    Sleep(3000);
    
    HMODULE hMod = FindActivationModule(hProcess);
    if (!hMod) {
        printf("[-] activation.x86.dll not found!\n");
        CloseHandle(hProcess);
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    
    MODULEINFO modInfo;
    GetModuleInformation(hProcess, hMod, &modInfo, sizeof(modInfo));
    
    unsigned char* base = (unsigned char*)modInfo.lpBaseOfDll;
    SIZE_T size = modInfo.SizeOfImage;
    
    printf("[*] Module size: 0x%zx bytes\n", size);
    
    int codePatches = PatchVerifyModeCode(hProcess, base);
    int cbPatch = PatchX509Callback(hProcess, base);
    int dataPatches = PatchVerifyModeData(hProcess, base, size);
    
    CloseHandle(hProcess);
    
    printf("\n====================================================\n");
    printf("  Results:\n");
    printf("    Code patches (verify_mode): %d/3\n", codePatches);
    printf("    Callback patch: %d/1\n", cbPatch);
    printf("    Data patches (SSL_CTX): %d\n", dataPatches);
    printf("====================================================\n");
    
    if (codePatches == 3 && cbPatch == 1) {
        printf("\n[+] All critical patches applied!\n");
    }
    
    printf("\nPress Enter to exit...");
    getchar();
    return 0;
}
