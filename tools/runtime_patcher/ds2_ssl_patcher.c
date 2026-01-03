
/*
 * Dead Space 2 Runtime SSL Patcher
 * 
 * Compile with MinGW (32-bit):
 *   i686-w64-mingw32-gcc -o ds2_ssl_patcher.exe ds2_ssl_patcher.c -lpsapi
 * 
 * Or MSVC:
 *   cl ds2_ssl_patcher.c /link psapi.lib
 */

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")

// Configuration
#define GAME_EXE "deadspace2.exe"
#define TARGET_DLL "activation.x86.dll"
#define PATCH_DELAY_MS 5000  // Wait for unpacking

// SSL_VERIFY modes
#define SSL_VERIFY_NONE 0
#define SSL_VERIFY_PEER 1
#define SSL_VERIFY_FAIL_IF_NO_PEER_CERT 2

typedef struct {
    DWORD offset;
    BYTE original;
    BYTE patched;
    const char* description;
} PatchInfo;

// Known patches for Steam version (MD5: fde0585b30ddb8deb1f60b5af9a4a001)
// These offsets are within the UNPACKED code, not the file offsets
// They need to be discovered through runtime analysis
PatchInfo g_knownPatches[] = {
    // These are placeholders - need runtime discovery
    // { 0x00000000, 0x01, 0x00, "SSL_VERIFY_PEER -> NONE" },
    { 0, 0, 0, NULL }  // Terminator
};

// Find process by name
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

// Find module base address in a process
BYTE* FindModuleBase(HANDLE hProcess, const char* moduleName) {
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
                return (BYTE*)modules[i];
            }
        }
    }
    
    return NULL;
}

// Read process memory
BOOL ReadMem(HANDLE hProcess, BYTE* address, void* buffer, SIZE_T size) {
    SIZE_T read;
    return ReadProcessMemory(hProcess, address, buffer, size, &read) && read == size;
}

// Write process memory
BOOL WriteMem(HANDLE hProcess, BYTE* address, void* data, SIZE_T size) {
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtectEx failed: %lu\n", GetLastError());
        return FALSE;
    }
    
    SIZE_T written;
    BOOL result = WriteProcessMemory(hProcess, address, data, size, &written);
    
    VirtualProtectEx(hProcess, address, size, oldProtect, &oldProtect);
    
    return result && written == size;
}

// Scan for pattern in process memory
BYTE* ScanPattern(HANDLE hProcess, BYTE* start, SIZE_T size, 
                  const BYTE* pattern, const char* mask, SIZE_T patLen) {
    BYTE* buffer = (BYTE*)malloc(size);
    if (!buffer) return NULL;
    
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, start, buffer, size, &read)) {
        free(buffer);
        return NULL;
    }
    
    for (SIZE_T i = 0; i < read - patLen; i++) {
        BOOL found = TRUE;
        for (SIZE_T j = 0; j < patLen; j++) {
            if (mask[j] == 'x' && buffer[i + j] != pattern[j]) {
                found = FALSE;
                break;
            }
        }
        if (found) {
            free(buffer);
            return start + i;
        }
    }
    
    free(buffer);
    return NULL;
}

// Find and patch SSL verification
int PatchSSLVerification(HANDLE hProcess, BYTE* dllBase) {
    printf("[*] Scanning for SSL verification patterns...\n");
    
    // Get module size
    MODULEINFO modInfo;
    if (!GetModuleInformation(hProcess, (HMODULE)dllBase, &modInfo, sizeof(modInfo))) {
        printf("[-] Failed to get module info\n");
        return 0;
    }
    
    SIZE_T moduleSize = modInfo.SizeOfImage;
    printf("[*] Module size: %zu bytes\n", moduleSize);
    
    // Read entire module
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
    
    printf("[*] Read %zu bytes from process\n", read);
    
    int patchCount = 0;
    
    // Strategy: Find "push 1/2/3" followed by CALL within ~20 bytes
    // These are SSL_CTX_set_verify or similar calls
    // 
    // More specifically, look for the pattern where we push callback (or 0),
    // then push verify_mode (1,2,3), then push ctx, then call
    
    // Pattern: 6A 01/02/03 followed by E8 within 20 bytes
    for (SIZE_T i = 0; i < read - 25; i++) {
        if (moduleData[i] == 0x6A && 
            (moduleData[i+1] == 0x01 || moduleData[i+1] == 0x02 || moduleData[i+1] == 0x03)) {
            
            // Check for CALL within next 20 bytes
            BOOL hasCall = FALSE;
            int callOffset = -1;
            for (int j = 2; j < 20; j++) {
                if (moduleData[i + j] == 0xE8) {
                    hasCall = TRUE;
                    callOffset = j;
                    break;
                }
            }
            
            if (!hasCall) continue;
            
            // Additional heuristic: check if there's a push before this
            // (the callback parameter for SSL_CTX_set_verify)
            BOOL likelySSL = FALSE;
            if (i >= 5) {
                // Check for "push 0" (6A 00) or "push imm32" (68 XX XX XX XX) before
                if ((moduleData[i-2] == 0x6A && moduleData[i-1] == 0x00) ||
                    moduleData[i-5] == 0x68) {
                    likelySSL = TRUE;
                }
            }
            
            // Also check if we're in code that references SSL strings
            // (This would require more sophisticated analysis)
            
            if (likelySSL || callOffset <= 10) {  // Short distance to call = more likely
                BYTE* patchAddr = dllBase + i + 1;  // +1 to patch the immediate value
                BYTE originalByte = moduleData[i + 1];
                BYTE patchByte = 0x00;  // SSL_VERIFY_NONE
                
                printf("[*] Potential SSL verify at offset 0x%zX (push %d)\n", i, originalByte);
                
                // Apply patch
                if (WriteMem(hProcess, patchAddr, &patchByte, 1)) {
                    printf("[+] Patched 0x%p: %02X -> %02X\n", patchAddr, originalByte, patchByte);
                    patchCount++;
                } else {
                    printf("[-] Failed to patch 0x%p\n", patchAddr);
                }
            }
        }
    }
    
    free(moduleData);
    return patchCount;
}

int main(int argc, char* argv[]) {
    printf("==============================================\n");
    printf("  Dead Space 2 Runtime SSL Patcher\n");
    printf("==============================================\n\n");
    
    // Find the game process
    printf("[*] Looking for %s...\n", GAME_EXE);
    
    DWORD pid = FindProcess(GAME_EXE);
    if (!pid) {
        printf("[!] Game not running. Please start Dead Space 2 first.\n");
        printf("[*] Waiting for game to start...\n");
        
        // Wait for game to start
        for (int i = 0; i < 60; i++) {
            Sleep(1000);
            pid = FindProcess(GAME_EXE);
            if (pid) break;
            printf(".");
        }
        printf("\n");
        
        if (!pid) {
            printf("[-] Timeout waiting for game\n");
            return 1;
        }
    }
    
    printf("[+] Found game process: PID %lu\n", pid);
    
    // Open the process
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    
    if (!hProcess) {
        printf("[-] Failed to open process: %lu\n", GetLastError());
        printf("[!] Try running as Administrator\n");
        return 1;
    }
    
    // Wait for DLL to be loaded and unpacked
    printf("[*] Waiting for %s to be loaded...\n", TARGET_DLL);
    
    BYTE* dllBase = NULL;
    for (int i = 0; i < 30; i++) {
        dllBase = FindModuleBase(hProcess, TARGET_DLL);
        if (dllBase) break;
        Sleep(1000);
        printf(".");
    }
    printf("\n");
    
    if (!dllBase) {
        printf("[-] Failed to find %s\n", TARGET_DLL);
        CloseHandle(hProcess);
        return 1;
    }
    
    printf("[+] Found %s at 0x%p\n", TARGET_DLL, dllBase);
    
    // Wait for unpacking to complete
    printf("[*] Waiting %d ms for unpacking...\n", PATCH_DELAY_MS);
    Sleep(PATCH_DELAY_MS);
    
    // Patch SSL verification
    int patches = PatchSSLVerification(hProcess, dllBase);
    
    if (patches > 0) {
        printf("\n[+] Successfully applied %d patches!\n", patches);
        printf("[*] SSL certificate verification has been disabled.\n");
        printf("[*] You can now connect to custom servers.\n");
    } else {
        printf("\n[-] No patches were applied.\n");
        printf("[*] The DLL structure may have changed or patching failed.\n");
    }
    
    CloseHandle(hProcess);
    
    printf("\nPress Enter to exit...");
    getchar();
    
    return patches > 0 ? 0 : 1;
}
