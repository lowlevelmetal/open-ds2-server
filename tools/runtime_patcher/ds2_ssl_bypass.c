/*
 * Dead Space 2 Complete SSL Bypass Patcher
 * 
 * This patcher applies TWO critical patches:
 * 
 * 1. Patches the code that sets verify_mode=1 to set verify_mode=0
 *    - This disables OpenSSL's certificate chain verification
 *    - Locations: 0xB1FF, 0xB6FC, 0xCB08
 * 
 * 2. Patches the X509 verification callback to accept ALL errors
 *    - The callback only accepted errors: 0x02, 0x15, 0x16, 0x06, 0x0F
 *    - But NOT 0x12 (DEPTH_ZERO_SELF_SIGNED_CERT) which our cert triggers
 *    - Location: 0x4F29 - change JNZ to JMP to accept path
 * 
 * Compile:
 *   i686-w64-mingw32-gcc -o ds2_ssl_bypass.exe ds2_ssl_bypass.c -lpsapi
 */

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>

//=============================================================================
// Configuration
//=============================================================================

typedef struct {
    DWORD offset;
    unsigned char original[10];
    int origLen;
    unsigned char patched[10];
    int patchLen;
    const char* description;
} Patch;

Patch g_patches[] = {
    // Patch 1: verify_mode = 1 -> 0 (ESI variant)
    {
        0xB1FF,
        {0xC7, 0x86, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, 10,
        {0xC7, 0x86, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 10,
        "MOV [ESI+0x130], 1 -> 0 (verify_mode)"
    },
    // Patch 2: verify_mode = 1 -> 0 (EDX variant)
    {
        0xB6FC,
        {0xC7, 0x82, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, 10,
        {0xC7, 0x82, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 10,
        "MOV [EDX+0x130], 1 -> 0 (verify_mode)"
    },
    // Patch 3: verify_mode = 1 -> 0 (EBX variant)
    {
        0xCB08,
        {0xC7, 0x83, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, 10,
        {0xC7, 0x83, 0x30, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, 10,
        "MOV [EBX+0x130], 1 -> 0 (verify_mode)"
    },
    // Patch 4: X509 verification callback - accept all errors
    {
        0x4F29,
        {0x0F, 0x85, 0xA4, 0x01, 0x00, 0x00}, 6,
        {0xE9, 0x90, 0x00, 0x00, 0x00, 0x90}, 6,
        "JNZ -> JMP in X509 callback (accept all cert errors)"
    },
};

#define NUM_PATCHES (sizeof(g_patches) / sizeof(g_patches[0]))

//=============================================================================
// Process/Module functions
//=============================================================================

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

//=============================================================================
// Patching
//=============================================================================

int ApplyPatch(HANDLE hProcess, unsigned char* moduleBase, Patch* patch) {
    unsigned char* patchAddr = moduleBase + patch->offset;
    
    printf("\n[*] %s\n", patch->description);
    printf("    Offset: 0x%lX, Address: 0x%p\n", patch->offset, patchAddr);
    
    // Read current bytes
    unsigned char currentBytes[16];
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, patchAddr, currentBytes, patch->patchLen, &bytesRead)) {
        printf("    [-] ReadProcessMemory failed: %lu\n", GetLastError());
        return 0;
    }
    
    printf("    Current: ");
    for (int i = 0; i < patch->patchLen; i++) printf("%02X ", currentBytes[i]);
    printf("\n");
    
    // Check if already patched
    if (memcmp(currentBytes, patch->patched, patch->patchLen) == 0) {
        printf("    [=] Already patched\n");
        return 1;
    }
    
    // Check if matches expected original (warning if not)
    if (memcmp(currentBytes, patch->original, patch->patchLen) != 0) {
        printf("    [!] WARNING: Bytes don't match expected original\n");
        printf("    Expected: ");
        for (int i = 0; i < patch->origLen; i++) printf("%02X ", patch->original[i]);
        printf("\n");
    }
    
    // Make memory writable
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, patchAddr, patch->patchLen, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("    [-] VirtualProtectEx failed: %lu\n", GetLastError());
        return 0;
    }
    
    // Write patched bytes
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, patchAddr, patch->patched, patch->patchLen, &bytesWritten)) {
        printf("    [-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualProtectEx(hProcess, patchAddr, patch->patchLen, oldProtect, &oldProtect);
        return 0;
    }
    
    // Flush instruction cache
    FlushInstructionCache(hProcess, patchAddr, patch->patchLen);
    
    // Restore protection
    VirtualProtectEx(hProcess, patchAddr, patch->patchLen, oldProtect, &oldProtect);
    
    // Verify
    if (!ReadProcessMemory(hProcess, patchAddr, currentBytes, patch->patchLen, &bytesRead)) {
        printf("    [-] Verification read failed\n");
        return 0;
    }
    
    if (memcmp(currentBytes, patch->patched, patch->patchLen) == 0) {
        printf("    [+] PATCHED successfully\n");
        return 1;
    } else {
        printf("    [-] Patch verification FAILED\n");
        return 0;
    }
}

//=============================================================================
// Main
//=============================================================================

int main(int argc, char* argv[]) {
    printf("====================================================\n");
    printf("  Dead Space 2 Complete SSL Bypass Patcher\n");
    printf("====================================================\n\n");
    
    printf("This patcher applies:\n");
    printf("  1. verify_mode=0 patches (3 locations)\n");
    printf("  2. X509 callback patch to accept self-signed certs\n\n");
    
    // Find process
    DWORD pid = FindProcessByName("deadspace2");
    if (pid == 0) pid = FindProcessByName("ds2");
    
    if (pid == 0) {
        printf("[-] Dead Space 2 not running. Start the game first!\n");
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    
    printf("[+] Found Dead Space 2: PID %lu\n", pid);
    
    // Open process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process: %lu (run as admin)\n", GetLastError());
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    
    // Wait for DLL to load and unpack
    printf("[*] Waiting 5 seconds for DLL to fully load...\n");
    Sleep(5000);
    
    // Find activation.x86.dll
    HMODULE hActivation = FindActivationModule(hProcess);
    if (!hActivation) {
        printf("[-] activation.x86.dll not found! Try later.\n");
        CloseHandle(hProcess);
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    
    unsigned char* moduleBase = (unsigned char*)hActivation;
    
    // Apply all patches
    int successCount = 0;
    for (int i = 0; i < NUM_PATCHES; i++) {
        if (ApplyPatch(hProcess, moduleBase, &g_patches[i])) {
            successCount++;
        }
    }
    
    CloseHandle(hProcess);
    
    printf("\n====================================================\n");
    printf("  Result: %d/%d patches applied\n", successCount, (int)NUM_PATCHES);
    printf("====================================================\n");
    
    if (successCount == NUM_PATCHES) {
        printf("\n[+] SUCCESS! SSL verification fully bypassed.\n");
        printf("[+] The game should now accept your server's certificate.\n");
    } else if (successCount > 0) {
        printf("\n[~] Partial success. Some patches may not have applied.\n");
    } else {
        printf("\n[-] All patches failed. Check if DLL is fully loaded.\n");
    }
    
    printf("\nPress Enter to exit...");
    getchar();
    return successCount > 0 ? 0 : 1;
}
