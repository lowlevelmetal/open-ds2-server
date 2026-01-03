/*
 * Dead Space 2 SSL Patcher v8 - Minimal Surgical Patch
 * 
 * The v7 patcher was too aggressive - it patched 2500+ locations and broke the game.
 * This version ONLY patches the specific SSL_set_verify calls and nothing else.
 * 
 * Target: The actual SSL_set_verify function call that sets verify_mode to 1
 * 
 * In OpenSSL 1.0.0b, SSL_set_verify looks like:
 *   void SSL_set_verify(SSL *s, int mode, verify_callback cb)
 *   {
 *       s->verify_mode = mode;  // offset 0x130 in SSL struct
 *       ...
 *   }
 * 
 * We need to patch the caller to pass mode=0 instead of mode=1
 * 
 * Build: i686-w64-mingw32-gcc -o ds2_ssl_patcher_v8.exe ds2_ssl_patcher_v8.c -lpsapi -static -O2
 */

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
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

BOOL WriteMem(HANDLE hProcess, BYTE* address, void* data, SIZE_T size) {
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    SIZE_T written;
    BOOL result = WriteProcessMemory(hProcess, address, data, size, &written);
    
    VirtualProtectEx(hProcess, address, size, oldProtect, &oldProtect);
    FlushInstructionCache(hProcess, address, size);
    
    return result && written == size;
}

int FindPattern(BYTE* data, SIZE_T dataSize, BYTE* pattern, SIZE_T patternSize, SIZE_T startOffset) {
    for (SIZE_T i = startOffset; i < dataSize - patternSize; i++) {
        if (memcmp(data + i, pattern, patternSize) == 0) {
            return (int)i;
        }
    }
    return -1;
}

int main(int argc, char* argv[]) {
    printf("===========================================\n");
    printf(" Dead Space 2 SSL Patcher v8\n");
    printf(" Minimal Surgical SSL_set_verify Patch\n");
    printf("===========================================\n\n");
    
    DWORD pid = FindProcess(GAME_EXE);
    if (pid == 0) {
        printf("[-] %s not found. Start the game first.\n", GAME_EXE);
        printf("[*] Press Enter to exit...\n");
        getchar();
        return 1;
    }
    
    printf("[+] Found process: PID %lu\n", pid);
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process (error %lu)\n", GetLastError());
        printf("    Try running as Administrator\n");
        getchar();
        return 1;
    }
    
    DWORD moduleSize = 0;
    BYTE* dllBase = FindModuleBase(hProcess, TARGET_DLL, &moduleSize);
    
    if (dllBase == NULL) {
        printf("[-] %s not found in process\n", TARGET_DLL);
        CloseHandle(hProcess);
        getchar();
        return 1;
    }
    
    printf("[+] Found %s at 0x%p (size: %lu bytes)\n", TARGET_DLL, dllBase, moduleSize);
    
    printf("[*] Reading module memory...\n");
    BYTE* moduleData = (BYTE*)malloc(moduleSize);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, dllBase, moduleData, moduleSize, &bytesRead)) {
        printf("[-] Failed to read module memory\n");
        free(moduleData);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Read %zu bytes\n", bytesRead);
    
    int totalPatches = 0;
    
    /* ============================================================
     * PATCH: Only the mov DWORD PTR [reg+0x130], 0x1 instructions
     * 
     * These are the ONLY instructions that set verify_mode = 1
     * Pattern: c7 8x 30 01 00 00 01 00 00 00
     * We change the 01 to 00 to set verify_mode = 0
     * ============================================================ */
    printf("\n[*] Patching SSL_set_verify (verify_mode = 1 -> 0)...\n");
    
    BYTE patterns[][10] = {
        {0xc7, 0x86, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, /* [esi+0x130] */
        {0xc7, 0x82, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, /* [edx+0x130] */
        {0xc7, 0x81, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, /* [ecx+0x130] */
        {0xc7, 0x83, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, /* [ebx+0x130] */
        {0xc7, 0x87, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, /* [edi+0x130] */
        {0xc7, 0x80, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00}, /* [eax+0x130] */
    };
    
    for (int p = 0; p < 6; p++) {
        int offset = 0;
        while ((offset = FindPattern(moduleData, bytesRead, patterns[p], 10, offset)) >= 0) {
            printf("    Found verify_mode=1 at +0x%X\n", offset);
            BYTE newVal = 0x00;
            if (WriteMem(hProcess, dllBase + offset + 6, &newVal, 1)) {
                totalPatches++;
                moduleData[offset + 6] = 0x00;
            }
            offset += 10;
        }
    }
    
    printf("[+] Patched %d verify_mode instructions\n", totalPatches);
    
    /* ============================================================
     * Summary
     * ============================================================ */
    printf("\n===========================================\n");
    printf("[*] Total patches applied: %d\n", totalPatches);
    
    if (totalPatches > 0) {
        printf("[+] SUCCESS: SSL_set_verify patched\n");
        printf("[*] Try connecting to server now\n");
    } else {
        printf("[-] No patches applied - patterns may have changed\n");
    }
    
    free(moduleData);
    CloseHandle(hProcess);
    
    printf("\n[*] Press Enter to exit...\n");
    getchar();
    return 0;
}
