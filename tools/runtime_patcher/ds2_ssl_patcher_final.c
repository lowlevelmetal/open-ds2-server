/*
 * Dead Space 2 SSL Certificate Bypass - Final Version
 * 
 * Based on complete reverse engineering of the X509 verification callback.
 * See docs/ssl_verification_analysis.md for full documentation.
 * 
 * PROBLEM: Error 0x12 (DEPTH_ZERO_SELF_SIGNED_CERT) reaches REJECT_PATH
 *          at 0x5cd3 and returns -1 (failure).
 * 
 * SOLUTION: Multiple patch points to ensure acceptance:
 * 1. NOP the JNE at 0x5b29 that sends unknown errors to reject
 * 2. Change "or eax,-1" to "xor eax,eax; inc eax" (return 1)
 * 3. NOP depth checks that reject based on chain depth
 * 
 * Build: i686-w64-mingw32-gcc -o ds2_ssl_patcher.exe ds2_ssl_patcher_final.c -lpsapi -Wall
 * Run:   wine ds2_ssl_patcher.exe (while game is at main menu)
 */

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

// Unique patterns from the X509 callback function

// Pattern 1: The JNE that rejects unknown errors
// Context: cmp ebx,0x4; je +9; cmp ebx,0xb; jne <reject>
// At offset 0x5b21 from function base
static const unsigned char PATTERN_ERROR_CHECK[] = {
    0x83, 0xfb, 0x04,       // cmp ebx, 0x4
    0x74, 0x09,             // je +9
    0x83, 0xfb, 0x0b,       // cmp ebx, 0xb
    0x0f, 0x85              // jne ... (followed by 4-byte offset)
};
#define PATTERN_ERROR_CHECK_LEN 10
#define PATCH_JNE_OFFSET 7  // Offset to JNE within pattern

// Pattern 2: The failure return
// Context: or eax,-1; call <epilog>
static const unsigned char PATTERN_RETURN_FAIL[] = {
    0x83, 0xc8, 0xff,       // or eax, 0xffffffff
    0xe8                    // call ...
};
#define PATTERN_RETURN_FAIL_LEN 4

// Pattern 3: Depth check for depth==4
// cmp esi,0x4; je <reject> (6-byte jump)
static const unsigned char PATTERN_DEPTH4[] = {
    0x83, 0xfe, 0x04,       // cmp esi, 0x4
    0x0f, 0x84              // je ... (followed by 4-byte offset)
};
#define PATTERN_DEPTH4_LEN 5

// Pattern 3b: Depth check for depth==3
static const unsigned char PATTERN_DEPTH3[] = {
    0x83, 0xfe, 0x03,       // cmp esi, 0x3
    0x0f, 0x84              // je ...
};
#define PATTERN_DEPTH3_LEN 5

// NOP sled for 6-byte patches
static const unsigned char NOP6[] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};

// Return 1 instead of -1
static const unsigned char RETURN_SUCCESS[] = {0x31, 0xc0, 0x40};  // xor eax,eax; inc eax

typedef struct {
    DWORD offset;
    const char* description;
} PatchLocation;

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

unsigned char* FindPattern(unsigned char* data, DWORD dataSize, 
                          const unsigned char* pattern, DWORD patternSize) {
    if (dataSize < patternSize) return NULL;
    
    for (DWORD i = 0; i <= dataSize - patternSize; i++) {
        if (memcmp(data + i, pattern, patternSize) == 0) {
            return data + i;
        }
    }
    return NULL;
}

int FindAllPatterns(unsigned char* data, DWORD dataSize,
                   const unsigned char* pattern, DWORD patternSize,
                   PatchLocation* locations, int maxLocations, const char* desc) {
    int count = 0;
    DWORD offset = 0;
    
    while (offset < dataSize - patternSize && count < maxLocations) {
        unsigned char* found = FindPattern(data + offset, dataSize - offset, pattern, patternSize);
        if (found) {
            locations[count].offset = (DWORD)(found - data);
            locations[count].description = desc;
            count++;
            offset = (DWORD)(found - data) + 1;
        } else {
            break;
        }
    }
    return count;
}

BOOL ApplyPatch(HANDLE hProcess, DWORD address, const unsigned char* patch, DWORD patchSize, const char* desc) {
    DWORD oldProtect;
    
    if (!VirtualProtectEx(hProcess, (LPVOID)address, patchSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("  [-] VirtualProtectEx failed for %s (error: %lu)\n", desc, GetLastError());
        return FALSE;
    }
    
    if (!WriteProcessMemory(hProcess, (LPVOID)address, patch, patchSize, NULL)) {
        printf("  [-] WriteProcessMemory failed for %s (error: %lu)\n", desc, GetLastError());
        VirtualProtectEx(hProcess, (LPVOID)address, patchSize, oldProtect, &oldProtect);
        return FALSE;
    }
    
    VirtualProtectEx(hProcess, (LPVOID)address, patchSize, oldProtect, &oldProtect);
    return TRUE;
}

int main() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     Dead Space 2 SSL Certificate Bypass - Final Version     ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Patches X509 verification to accept self-signed certs      ║\n");
    printf("║  Based on complete reverse engineering of activation.dll    ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    // Find Dead Space 2 process
    printf("[*] Looking for deadspace2.exe...\n");
    DWORD pid = FindProcessByName("deadspace2.exe");
    if (!pid) {
        printf("[-] Dead Space 2 is not running!\n");
        printf("\n");
        printf("Instructions:\n");
        printf("  1. Start Dead Space 2 from Steam\n");
        printf("  2. Wait until you reach the main menu\n");
        printf("  3. Run this patcher\n");
        printf("  4. Try connecting to multiplayer\n");
        printf("\n");
        return 1;
    }
    printf("[+] Found deadspace2.exe (PID: %lu)\n", pid);
    
    // Open process with full access
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process (error: %lu)\n", GetLastError());
        printf("    Try running as administrator\n");
        return 1;
    }
    printf("[+] Process handle acquired\n");
    
    // Find activation.x86.dll module
    DWORD moduleSize = 0;
    DWORD moduleBase = FindModule(hProcess, "activation.x86.dll", &moduleSize);
    if (!moduleBase) {
        printf("[-] activation.x86.dll not found in process\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Found activation.x86.dll\n");
    printf("    Base: 0x%08lX\n", moduleBase);
    printf("    Size: %lu bytes (%.2f MB)\n", moduleSize, moduleSize / (1024.0 * 1024.0));
    
    // Check if DLL is unpacked (should be ~6.79 MB)
    if (moduleSize < 6000000) {
        printf("[-] Module size too small (%lu bytes)\n", moduleSize);
        printf("    The DLL protection has not yet unpacked.\n");
        printf("    Please wait at the main menu for 10-15 seconds and try again.\n");
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Module size confirms DLL is unpacked\n");
    
    // Read entire module into memory
    printf("[*] Reading module memory...\n");
    unsigned char* buffer = (unsigned char*)malloc(moduleSize);
    if (!buffer) {
        printf("[-] Failed to allocate memory buffer\n");
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
    
    printf("\n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("                    APPLYING PATCHES                           \n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("\n");
    
    int patchCount = 0;
    int totalPatches = 0;
    PatchLocation locations[20];
    int found;
    
    // ═══════════════════════════════════════════════════════════════
    // PATCH 1: NOP the JNE that rejects unknown error codes
    // ═══════════════════════════════════════════════════════════════
    printf("[PATCH 1] Error code routing JNE\n");
    printf("  Pattern: cmp ebx,4; je; cmp ebx,0xb; jne\n");
    
    found = FindAllPatterns(buffer, moduleSize, PATTERN_ERROR_CHECK, PATTERN_ERROR_CHECK_LEN,
                           locations, 20, "JNE error reject");
    printf("  Found: %d matches\n", found);
    
    for (int i = 0; i < found; i++) {
        totalPatches++;
        DWORD patchOffset = locations[i].offset + PATCH_JNE_OFFSET;
        DWORD patchAddr = moduleBase + patchOffset;
        
        // Verify it's actually a JNE (0F 85)
        if (buffer[patchOffset] == 0x0f && buffer[patchOffset+1] == 0x85) {
            printf("  [%d] JNE at 0x%08lX (offset 0x%lX)\n", i+1, patchAddr, patchOffset);
            
            if (ApplyPatch(hProcess, patchAddr, NOP6, 6, "JNE->NOP")) {
                printf("      -> Patched to NOP x6\n");
                patchCount++;
            }
        } else {
            printf("  [%d] Skipping - not a JNE at offset 0x%lX\n", i+1, patchOffset);
        }
    }
    printf("\n");
    
    // ═══════════════════════════════════════════════════════════════
    // PATCH 2: Change return -1 to return 1
    // ═══════════════════════════════════════════════════════════════
    printf("[PATCH 2] Failure return value\n");
    printf("  Pattern: or eax,-1; call\n");
    
    found = FindAllPatterns(buffer, moduleSize, PATTERN_RETURN_FAIL, PATTERN_RETURN_FAIL_LEN,
                           locations, 20, "return -1");
    printf("  Found: %d matches\n", found);
    
    for (int i = 0; i < found; i++) {
        totalPatches++;
        DWORD patchAddr = moduleBase + locations[i].offset;
        
        printf("  [%d] Return at 0x%08lX (offset 0x%lX)\n", i+1, patchAddr, locations[i].offset);
        
        if (ApplyPatch(hProcess, patchAddr, RETURN_SUCCESS, 3, "ret -1 -> ret 1")) {
            printf("      -> Patched to: xor eax,eax; inc eax (return 1)\n");
            patchCount++;
        }
    }
    printf("\n");
    
    // ═══════════════════════════════════════════════════════════════
    // PATCH 3: NOP depth==4 check
    // ═══════════════════════════════════════════════════════════════
    printf("[PATCH 3] Depth==4 chain check\n");
    printf("  Pattern: cmp esi,4; je\n");
    
    found = FindAllPatterns(buffer, moduleSize, PATTERN_DEPTH4, PATTERN_DEPTH4_LEN,
                           locations, 20, "depth==4");
    printf("  Found: %d matches\n", found);
    
    for (int i = 0; i < found; i++) {
        totalPatches++;
        DWORD patchOffset = locations[i].offset + 3;  // Skip CMP, patch JE
        DWORD patchAddr = moduleBase + patchOffset;
        
        printf("  [%d] JE at 0x%08lX (offset 0x%lX)\n", i+1, patchAddr, patchOffset);
        
        if (ApplyPatch(hProcess, patchAddr, NOP6, 6, "depth4 JE->NOP")) {
            printf("      -> Patched to NOP x6\n");
            patchCount++;
        }
    }
    printf("\n");
    
    // ═══════════════════════════════════════════════════════════════
    // PATCH 4: NOP depth==3 check
    // ═══════════════════════════════════════════════════════════════
    printf("[PATCH 4] Depth==3 chain check\n");
    printf("  Pattern: cmp esi,3; je\n");
    
    found = FindAllPatterns(buffer, moduleSize, PATTERN_DEPTH3, PATTERN_DEPTH3_LEN,
                           locations, 20, "depth==3");
    printf("  Found: %d matches\n", found);
    
    for (int i = 0; i < found; i++) {
        totalPatches++;
        DWORD patchOffset = locations[i].offset + 3;
        DWORD patchAddr = moduleBase + patchOffset;
        
        printf("  [%d] JE at 0x%08lX (offset 0x%lX)\n", i+1, patchAddr, patchOffset);
        
        if (ApplyPatch(hProcess, patchAddr, NOP6, 6, "depth3 JE->NOP")) {
            printf("      -> Patched to NOP x6\n");
            patchCount++;
        }
    }
    printf("\n");
    
    // Cleanup
    free(buffer);
    CloseHandle(hProcess);
    
    // Summary
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("                         SUMMARY                               \n");
    printf("═══════════════════════════════════════════════════════════════\n");
    printf("\n");
    printf("  Patches attempted: %d\n", totalPatches);
    printf("  Patches applied:   %d\n", patchCount);
    printf("\n");
    
    if (patchCount > 0) {
        printf("╔══════════════════════════════════════════════════════════════╗\n");
        printf("║                     PATCHING SUCCESSFUL!                     ║\n");
        printf("╠══════════════════════════════════════════════════════════════╣\n");
        printf("║  The SSL certificate verification has been bypassed.         ║\n");
        printf("║  You should now be able to connect to your custom server.    ║\n");
        printf("║                                                              ║\n");
        printf("║  Make sure your server is running and hosts file is set up.  ║\n");
        printf("╚══════════════════════════════════════════════════════════════╝\n");
        return 0;
    } else {
        printf("╔══════════════════════════════════════════════════════════════╗\n");
        printf("║                      PATCHING FAILED                         ║\n");
        printf("╠══════════════════════════════════════════════════════════════╣\n");
        printf("║  No patches were applied. Possible causes:                   ║\n");
        printf("║  - The DLL structure may have changed                        ║\n");
        printf("║  - Memory protection prevented writes                        ║\n");
        printf("║  - The DLL may not be fully unpacked yet                     ║\n");
        printf("║                                                              ║\n");
        printf("║  Try waiting longer at the main menu and run again.          ║\n");
        printf("╚══════════════════════════════════════════════════════════════╝\n");
        return 1;
    }
}
