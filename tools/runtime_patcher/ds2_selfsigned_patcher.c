/*
 * Dead Space 2 Self-Signed Certificate Patcher
 * 
 * The game has a verification callback that only accepts certain X509 errors:
 *   0x02 - X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
 *   0x15 - X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
 *   0x16 - X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN
 *   0x06 - X509_V_ERR_CERT_NOT_YET_VALID
 *   0x0F - X509_V_ERR_...
 * 
 * But it does NOT accept:
 *   0x12 (18) - X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
 * 
 * This patch changes the JNZ that rejects unknown errors to JMP so ALL errors are accepted.
 * 
 * Location: 0x4F29 (relative to module base)
 * Original: 0F 85 A4 01 00 00  (JNZ +0x1A4)
 * Patched:  E9 92 00 00 00 90  (JMP +0x92 ; NOP) - jumps to accept path
 * 
 * Compile for 32-bit Windows:
 *   i686-w64-mingw32-gcc -o ds2_selfsigned_patcher.exe ds2_selfsigned_patcher.c -lpsapi
 */

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>

// The callback is in activation.x86.dll
// Offset from module base: 0x4F29
// 
// We want to change:
//   0F 85 A4 01 00 00  JNZ rel32 (+0x1A4 -> error reject path)
// To:
//   E9 91 00 00 00 90  JMP rel32 (+0x91 -> error accept path at 0x4FBF) + NOP
//
// Actually, let me recalculate:
// From 0x4F29+6 = 0x4F2F to 0x4FBF = 0x90 bytes forward
// JMP rel32 encoding: E9 XX XX XX XX

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

int PatchVerificationCallback(HANDLE hProcess, HMODULE hModule) {
    unsigned char* moduleBase = (unsigned char*)hModule;
    
    // Offset of the JNZ instruction in the verification callback
    DWORD offset = 0x4F29;
    unsigned char* patchAddr = moduleBase + offset;
    
    // Original bytes: 0F 85 A4 01 00 00 (JNZ +0x1A4)
    unsigned char originalBytes[] = {0x0F, 0x85, 0xA4, 0x01, 0x00, 0x00};
    
    // New bytes: E9 90 00 00 00 90 (JMP +0x90 to 0x4FBF, then NOP)
    // From 0x4F29+5 = 0x4F2E, jump to 0x4FBF = offset 0x91
    unsigned char patchedBytes[] = {0xE9, 0x90, 0x00, 0x00, 0x00, 0x90};
    
    printf("[*] Patching verification callback at offset 0x%lX\n", offset);
    printf("[*] Target address: 0x%p\n", patchAddr);
    
    // Read current bytes
    unsigned char currentBytes[6];
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, patchAddr, currentBytes, 6, &bytesRead)) {
        printf("[-] ReadProcessMemory failed: %lu\n", GetLastError());
        return 0;
    }
    
    printf("[*] Current bytes: ");
    for (int i = 0; i < 6; i++) printf("%02X ", currentBytes[i]);
    printf("\n");
    
    // Check if already patched
    if (memcmp(currentBytes, patchedBytes, 6) == 0) {
        printf("[+] Already patched!\n");
        return 1;
    }
    
    // Check if matches expected original
    if (memcmp(currentBytes, originalBytes, 6) != 0) {
        printf("[!] WARNING: Current bytes don't match expected original!\n");
        printf("[!] Expected: ");
        for (int i = 0; i < 6; i++) printf("%02X ", originalBytes[i]);
        printf("\n");
        printf("[!] Proceeding anyway...\n");
    }
    
    // Make memory writable
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, patchAddr, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("[-] VirtualProtectEx failed: %lu\n", GetLastError());
        return 0;
    }
    
    // Write patched bytes
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, patchAddr, patchedBytes, 6, &bytesWritten)) {
        printf("[-] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualProtectEx(hProcess, patchAddr, 6, oldProtect, &oldProtect);
        return 0;
    }
    
    printf("[+] Patched %zu bytes\n", bytesWritten);
    
    // Flush instruction cache
    FlushInstructionCache(hProcess, patchAddr, 6);
    
    // Restore protection
    VirtualProtectEx(hProcess, patchAddr, 6, oldProtect, &oldProtect);
    
    // Verify
    if (!ReadProcessMemory(hProcess, patchAddr, currentBytes, 6, &bytesRead)) {
        printf("[-] Verification read failed\n");
        return 0;
    }
    
    printf("[*] Verified bytes: ");
    for (int i = 0; i < 6; i++) printf("%02X ", currentBytes[i]);
    printf("\n");
    
    if (memcmp(currentBytes, patchedBytes, 6) == 0) {
        printf("[+] Verification callback patched successfully!\n");
        return 1;
    } else {
        printf("[-] Patch verification failed\n");
        return 0;
    }
}

int main(int argc, char* argv[]) {
    printf("=== Dead Space 2 Self-Signed Certificate Patcher ===\n");
    printf("Patches the X509 verification callback to accept self-signed certs\n\n");
    
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
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process: %lu\n", GetLastError());
        printf("    Try running as Administrator.\n");
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    
    printf("[*] Waiting 5 seconds for DLL to load and unpack...\n");
    Sleep(5000);
    
    HMODULE hActivation = FindActivationModule(hProcess);
    if (!hActivation) {
        printf("[-] activation.x86.dll not found!\n");
        CloseHandle(hProcess);
        printf("\nPress Enter to exit...");
        getchar();
        return 1;
    }
    
    int success = PatchVerificationCallback(hProcess, hActivation);
    
    CloseHandle(hProcess);
    
    if (success) {
        printf("\n[+] SUCCESS: Verification callback patched\n");
        printf("[+] Self-signed certificates should now be accepted!\n");
    } else {
        printf("\n[-] Patching failed\n");
    }
    
    printf("\nPress Enter to exit...");
    getchar();
    return success ? 0 : 1;
}
