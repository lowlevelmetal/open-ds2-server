/*
 * Dead Space 2 Memory Dumper
 * Dumps the unpacked activation.x86.dll from memory for analysis
 * 
 * Build: i686-w64-mingw32-gcc -o ds2_dumper.exe ds2_dumper.c -lpsapi -static
 */

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdint.h>
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

int main(int argc, char* argv[]) {
    printf("==============================================\n");
    printf("  Dead Space 2 Memory Dumper\n");
    printf("==============================================\n\n");
    
    printf("[*] Looking for %s...\n", GAME_EXE);
    
    DWORD pid = FindProcess(GAME_EXE);
    if (!pid) {
        printf("[-] Game not running!\n");
        return 1;
    }
    
    printf("[+] Found game process: PID %lu\n", pid);
    
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    
    if (!hProcess) {
        printf("[-] Failed to open process: %lu\n", GetLastError());
        return 1;
    }
    
    BYTE* dllBase = NULL;
    DWORD moduleSize = 0;
    dllBase = FindModuleBase(hProcess, TARGET_DLL, &moduleSize);
    
    if (!dllBase) {
        printf("[-] Failed to find %s\n", TARGET_DLL);
        CloseHandle(hProcess);
        return 1;
    }
    
    printf("[+] Found %s at 0x%p (size: %lu bytes)\n", TARGET_DLL, dllBase, moduleSize);
    
    // Allocate buffer and read module
    BYTE* moduleData = (BYTE*)malloc(moduleSize);
    if (!moduleData) {
        printf("[-] Memory allocation failed\n");
        CloseHandle(hProcess);
        return 1;
    }
    
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, dllBase, moduleData, moduleSize, &read)) {
        printf("[-] Failed to read module memory: %lu\n", GetLastError());
        free(moduleData);
        CloseHandle(hProcess);
        return 1;
    }
    
    printf("[+] Read %zu bytes from process\n", read);
    
    // Write to file
    const char* outputFile = "activation_dumped.bin";
    FILE* f = fopen(outputFile, "wb");
    if (!f) {
        printf("[-] Failed to create output file\n");
        free(moduleData);
        CloseHandle(hProcess);
        return 1;
    }
    
    fwrite(moduleData, 1, read, f);
    fclose(f);
    
    printf("[+] Dumped to %s\n", outputFile);
    
    // Now let's search for SSL-related strings
    printf("\n[*] Searching for SSL-related strings...\n");
    
    const char* sslStrings[] = {
        "SSL_CTX_set_verify",
        "SSL_get_verify_result",
        "X509_verify_cert",
        "ssl_verify",
        "certificate",
        "verify",
        "SSL_connect",
        "SSL_CTX_new",
        "SSL_new",
        "gosredirector",
        "ea.com",
        "BEGIN CERTIFICATE",
        "-----BEGIN",
        NULL
    };
    
    for (int s = 0; sslStrings[s] != NULL; s++) {
        const char* needle = sslStrings[s];
        size_t needleLen = strlen(needle);
        
        for (SIZE_T i = 0; i < read - needleLen; i++) {
            if (memcmp(moduleData + i, needle, needleLen) == 0) {
                printf("[+] Found '%s' at offset 0x%zX (VA: 0x%p)\n", 
                       needle, i, dllBase + i);
            }
        }
    }
    
    // Search for potential verify callback patterns
    printf("\n[*] Analyzing code patterns...\n");
    
    // Look for SSL_CTX_set_verify call pattern:
    // push callback
    // push mode (1, 2, or 3)
    // push/mov ctx
    // call SSL_CTX_set_verify
    
    int patternCount = 0;
    for (SIZE_T i = 0; i < read - 20; i++) {
        // Look for: push imm8 (6A 01/02/03) 
        if (moduleData[i] == 0x6A && moduleData[i+1] >= 1 && moduleData[i+1] <= 3) {
            // Check for call within next 15 bytes
            for (int j = 2; j < 15; j++) {
                if (moduleData[i+j] == 0xE8) {  // call rel32
                    // Calculate call target
                    int32_t offset = *(int32_t*)(moduleData + i + j + 1);
                    SIZE_T callTarget = i + j + 5 + offset;
                    
                    // Check if there's a push before (callback address)
                    BOOL hasPushBefore = FALSE;
                    for (int k = 1; k < 10; k++) {
                        if (i >= k && moduleData[i-k] == 0x68) {
                            hasPushBefore = TRUE;
                            break;
                        }
                    }
                    
                    if (hasPushBefore && patternCount < 50) {
                        printf("[+] SSL_CTX_set_verify pattern at 0x%zX: push %d, call to 0x%zX\n",
                               i, moduleData[i+1], callTarget);
                        patternCount++;
                    }
                    break;
                }
            }
        }
    }
    
    printf("\n[+] Found %d potential SSL_CTX_set_verify patterns\n", patternCount);
    
    free(moduleData);
    CloseHandle(hProcess);
    
    printf("\nDump complete. Analyze activation_dumped.bin with a disassembler.\n");
    printf("Press Enter to exit...");
    getchar();
    
    return 0;
}
