/*
 * Dead Space 2 SSL Verification CODE Patcher
 * 
 * This patches the actual INSTRUCTIONS that set verify_mode=1 to set verify_mode=0 instead.
 * 
 * The code patterns we need to patch:
 *   C7 86 30 01 00 00 01 00 00 00  ->  C7 86 30 01 00 00 00 00 00 00  (mov [esi+0x130], 1 -> 0)
 *   C7 82 30 01 00 00 01 00 00 00  ->  C7 82 30 01 00 00 00 00 00 00  (mov [edx+0x130], 1 -> 0)
 *   C7 83 30 01 00 00 01 00 00 00  ->  C7 83 30 01 00 00 00 00 00 00  (mov [ebx+0x130], 1 -> 0)
 * 
 * Compile for 32-bit Windows (cross-compile):
 *   i686-w64-mingw32-gcc -o ds2_code_patcher.exe ds2_code_patcher.c -lpsapi
 */

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>

// Pattern: MOV DWORD PTR [reg+0x130], 1
// The immediate value is at offset +6 in the instruction
// Instruction is 10 bytes total

typedef struct {
    unsigned char pattern[10];
    unsigned char patched[10];
    const char* description;
} CodePatch;

CodePatch patches[] = {
    {
        {0xC7, 0x86, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},  // mov [esi+0x130], 1
        {0xC7, 0x86, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // mov [esi+0x130], 0
        "MOV [ESI+0x130], 1 -> 0 (set verify_mode=0)"
    },
    {
        {0xC7, 0x82, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},  // mov [edx+0x130], 1
        {0xC7, 0x82, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // mov [edx+0x130], 0
        "MOV [EDX+0x130], 1 -> 0 (set verify_mode=0)"
    },
    {
        {0xC7, 0x83, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},  // mov [ebx+0x130], 1
        {0xC7, 0x83, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // mov [ebx+0x130], 0
        "MOV [EBX+0x130], 1 -> 0 (set verify_mode=0)"
    },
    {
        {0xC7, 0x81, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},  // mov [ecx+0x130], 1
        {0xC7, 0x81, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // mov [ecx+0x130], 0
        "MOV [ECX+0x130], 1 -> 0 (set verify_mode=0)"
    },
    {
        {0xC7, 0x87, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},  // mov [edi+0x130], 1
        {0xC7, 0x87, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // mov [edi+0x130], 0
        "MOV [EDI+0x130], 1 -> 0 (set verify_mode=0)"
    },
    {
        {0xC7, 0x80, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},  // mov [eax+0x130], 1
        {0xC7, 0x80, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},  // mov [eax+0x130], 0
        "MOV [EAX+0x130], 1 -> 0 (set verify_mode=0)"
    }
};

#define NUM_PATCHES (sizeof(patches) / sizeof(patches[0]))

HMODULE FindActivationModule(HANDLE hProcess) {
    HMODULE hMods[1024];
    DWORD cbNeeded;
    char moduleName[MAX_PATH];
    
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            if (GetModuleBaseNameA(hProcess, hMods[i], moduleName, sizeof(moduleName))) {
                // Convert to lowercase for comparison
                for (int j = 0; moduleName[j]; j++) {
                    if (moduleName[j] >= 'A' && moduleName[j] <= 'Z')
                        moduleName[j] += 32;
                }
                
                if (strstr(moduleName, "activation") != NULL &&
                    (strstr(moduleName, ".dll") != NULL || strstr(moduleName, ".x86") != NULL)) {
                    printf("[+] Found module: %s at 0x%p\n", moduleName, hMods[i]);
                    return hMods[i];
                }
            }
        }
    }
    return NULL;
}

int SearchAndPatchCode(HANDLE hProcess, HMODULE hModule) {
    MODULEINFO modInfo;
    if (!GetModuleInformation(hProcess, hModule, &modInfo, sizeof(modInfo))) {
        printf("[-] GetModuleInformation failed: %lu\n", GetLastError());
        return 0;
    }
    
    SIZE_T moduleSize = modInfo.SizeOfImage;
    unsigned char* moduleBase = (unsigned char*)modInfo.lpBaseOfDll;
    
    printf("[*] Module base: 0x%p, size: 0x%zx\n", moduleBase, moduleSize);
    
    // Read entire module into local buffer
    unsigned char* buffer = malloc(moduleSize);
    if (!buffer) {
        printf("[-] Memory allocation failed\n");
        return 0;
    }
    
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, moduleBase, buffer, moduleSize, &bytesRead)) {
        printf("[-] ReadProcessMemory failed: %lu\n", GetLastError());
        free(buffer);
        return 0;
    }
    
    printf("[*] Read %zu bytes from process\n", bytesRead);
    
    int totalPatched = 0;
    
    // Search for each pattern
    for (int p = 0; p < NUM_PATCHES; p++) {
        printf("[*] Searching for: %s\n", patches[p].description);
        
        for (SIZE_T i = 0; i < bytesRead - 10; i++) {
            int match = 1;
            for (int j = 0; j < 10; j++) {
                if (buffer[i + j] != patches[p].pattern[j]) {
                    match = 0;
                    break;
                }
            }
            
            if (match) {
                unsigned char* patchAddr = moduleBase + i;
                printf("[+] FOUND at offset 0x%zx (VA 0x%p)\n", i, patchAddr);
                
                // Make memory writable
                DWORD oldProtect;
                if (!VirtualProtectEx(hProcess, patchAddr, 10, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    printf("[-] VirtualProtectEx failed: %lu\n", GetLastError());
                    continue;
                }
                
                // Write patched bytes
                SIZE_T bytesWritten;
                if (WriteProcessMemory(hProcess, patchAddr, patches[p].patched, 10, &bytesWritten)) {
                    printf("[+] PATCHED: %zu bytes written\n", bytesWritten);
                    totalPatched++;
                    
                    // Flush instruction cache
                    FlushInstructionCache(hProcess, patchAddr, 10);
                } else {
                    printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
                }
                
                // Restore protection
                VirtualProtectEx(hProcess, patchAddr, 10, oldProtect, &oldProtect);
            }
        }
    }
    
    free(buffer);
    return totalPatched;
}

DWORD FindProcessByName(const char* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    
    if (Process32First(snapshot, &pe32)) {
        do {
            // Convert to lowercase for comparison
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

int main(int argc, char* argv[]) {
    printf("=== Dead Space 2 SSL Verification CODE Patcher ===\n");
    printf("Patches the actual MOV [reg+0x130],1 instructions to set verify_mode=0\n\n");
    
    // Find Dead Space 2 process
    DWORD pid = FindProcessByName("deadspace2");
    if (pid == 0) {
        pid = FindProcessByName("ds2");
    }
    
    if (pid == 0) {
        printf("[-] Dead Space 2 process not found!\n");
        printf("    Please start the game first.\n");
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    
    printf("[+] Found Dead Space 2 process: PID %lu\n", pid);
    
    // Open process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process: %lu\n", GetLastError());
        printf("    Try running as Administrator.\n");
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    
    // Find activation.x86.dll
    printf("[*] Looking for activation.x86.dll...\n");
    
    // Wait a bit for DLL to load and unpack
    printf("[*] Waiting 5 seconds for DLL to fully load and unpack...\n");
    Sleep(5000);
    
    HMODULE hActivation = FindActivationModule(hProcess);
    if (!hActivation) {
        printf("[-] activation.x86.dll not found!\n");
        printf("    The game might not have loaded the DLL yet.\n");
        printf("    Try running again after reaching the main menu.\n");
        CloseHandle(hProcess);
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    
    // Search and patch
    int patchCount = SearchAndPatchCode(hProcess, hActivation);
    
    CloseHandle(hProcess);
    
    if (patchCount > 0) {
        printf("\n[+] SUCCESS: Patched %d code locations\n", patchCount);
        printf("[+] SSL verification code modified to set verify_mode=0\n");
    } else {
        printf("\n[-] No patterns found to patch\n");
        printf("    The code might already be patched or has different patterns.\n");
    }
    
    printf("\nPress Enter to exit...");
    getchar();
    return patchCount > 0 ? 0 : 1;
}
