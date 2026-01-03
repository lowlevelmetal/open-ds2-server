/*
 * Dead Space 2 SSL Verification Patcher
 * 
 * This patcher:
 * 1. Waits for game to start and DLL to unpack
 * 2. Scans for verify_mode patterns
 * 3. Logs exactly what it finds
 * 4. Patches and verifies the patch
 */

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define GAME_EXE "deadspace2.exe"
#define TARGET_DLL "activation.x86.dll"
#define LOG_FILE "ds2_verify_patcher.log"

FILE* g_log = NULL;

void log_msg(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, args);
    
    printf("%s", buf);
    
    if (g_log) {
        fprintf(g_log, "%s", buf);
        fflush(g_log);
    }
    
    va_end(args);
}

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

void hexdump(const BYTE* data, int len, int offset) {
    log_msg("    %08X: ", offset);
    for (int i = 0; i < len; i++) {
        log_msg("%02X ", data[i]);
    }
    log_msg("\n");
}

int main() {
    g_log = fopen(LOG_FILE, "w");
    
    time_t now = time(NULL);
    log_msg("=================================================\n");
    log_msg(" Dead Space 2 SSL Verification Patcher\n");
    log_msg(" Started: %s", ctime(&now));
    log_msg("=================================================\n\n");
    
    // Find or wait for game
    log_msg("[*] Looking for %s...\n", GAME_EXE);
    
    DWORD pid = 0;
    for (int i = 0; i < 120; i++) {  // Wait up to 2 minutes
        pid = FindProcess(GAME_EXE);
        if (pid) break;
        Sleep(1000);
        if (i % 10 == 0) log_msg("    Waiting... (%d seconds)\n", i);
    }
    
    if (!pid) {
        log_msg("[-] Game not found after 2 minutes\n");
        if (g_log) fclose(g_log);
        return 1;
    }
    
    log_msg("[+] Found game: PID %lu\n", pid);
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        log_msg("[-] Failed to open process: error %lu\n", GetLastError());
        if (g_log) fclose(g_log);
        return 1;
    }
    
    // Wait for DLL to load
    log_msg("[*] Waiting for %s to load...\n", TARGET_DLL);
    
    BYTE* dllBase = NULL;
    DWORD dllSize = 0;
    
    for (int i = 0; i < 60; i++) {
        dllBase = FindModuleBase(hProcess, TARGET_DLL, &dllSize);
        if (dllBase) break;
        Sleep(1000);
        if (i % 10 == 0) log_msg("    Waiting... (%d seconds)\n", i);
    }
    
    if (!dllBase) {
        log_msg("[-] DLL not found\n");
        CloseHandle(hProcess);
        if (g_log) fclose(g_log);
        return 1;
    }
    
    log_msg("[+] Found %s at 0x%p (size: %lu)\n", TARGET_DLL, dllBase, dllSize);
    
    // Wait for Themida to unpack
    log_msg("[*] Waiting 10 seconds for Themida unpacking...\n");
    Sleep(10000);
    
    // Re-check module (base might change)
    BYTE* newBase = FindModuleBase(hProcess, TARGET_DLL, &dllSize);
    if (newBase != dllBase) {
        log_msg("[!] DLL base changed: 0x%p -> 0x%p\n", dllBase, newBase);
        dllBase = newBase;
    }
    
    // Read DLL memory
    log_msg("[*] Reading DLL memory...\n");
    
    BYTE* dllData = (BYTE*)malloc(dllSize);
    SIZE_T bytesRead = 0;
    
    if (!ReadProcessMemory(hProcess, dllBase, dllData, dllSize, &bytesRead)) {
        log_msg("[-] Failed to read DLL memory: error %lu\n", GetLastError());
        free(dllData);
        CloseHandle(hProcess);
        if (g_log) fclose(g_log);
        return 1;
    }
    
    log_msg("[+] Read %zu bytes\n", bytesRead);
    
    // Scan for all verify_mode patterns
    log_msg("\n[*] Scanning for verify_mode patterns...\n");
    log_msg("    Pattern: C7 8x 30 01 00 00 XX 00 00 00\n");
    log_msg("    (mov dword ptr [reg+0x130], XX)\n\n");
    
    int foundVerify1 = 0;
    int foundVerify0 = 0;
    int patched = 0;
    
    // Scan for all mov [reg+0x130], value patterns
    for (DWORD i = 0; i < bytesRead - 10; i++) {
        // Check for mov dword ptr [reg+0x130], imm32
        // C7 8x 30 01 00 00 value32
        if (dllData[i] == 0xC7 && 
            (dllData[i+1] >= 0x80 && dllData[i+1] <= 0x87) &&
            dllData[i+2] == 0x30 && dllData[i+3] == 0x01 &&
            dllData[i+4] == 0x00 && dllData[i+5] == 0x00 &&
            dllData[i+7] == 0x00 && dllData[i+8] == 0x00 && dllData[i+9] == 0x00) {
            
            BYTE value = dllData[i+6];
            const char* regname = "???";
            switch(dllData[i+1]) {
                case 0x80: regname = "eax"; break;
                case 0x81: regname = "ecx"; break;
                case 0x82: regname = "edx"; break;
                case 0x83: regname = "ebx"; break;
                case 0x84: regname = "esp"; break;
                case 0x85: regname = "ebp"; break;
                case 0x86: regname = "esi"; break;
                case 0x87: regname = "edi"; break;
            }
            
            if (value == 1) {
                log_msg("  [VERIFY=1] +0x%05X: mov [%s+0x130], 1\n", i, regname);
                hexdump(dllData + i, 10, i);
                foundVerify1++;
                
                // Patch it!
                DWORD oldProtect;
                BYTE zero = 0;
                if (VirtualProtectEx(hProcess, dllBase + i + 6, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    SIZE_T written;
                    if (WriteProcessMemory(hProcess, dllBase + i + 6, &zero, 1, &written)) {
                        FlushInstructionCache(hProcess, dllBase + i + 6, 1);
                        dllData[i + 6] = 0;
                        log_msg("      -> PATCHED to 0!\n");
                        patched++;
                    }
                    VirtualProtectEx(hProcess, dllBase + i + 6, 1, oldProtect, &oldProtect);
                }
            } else if (value == 0) {
                log_msg("  [VERIFY=0] +0x%05X: mov [%s+0x130], 0\n", i, regname);
                foundVerify0++;
            }
        }
    }
    
    log_msg("\n=================================================\n");
    log_msg(" Summary:\n");
    log_msg("   Found verify_mode = 1: %d locations\n", foundVerify1);
    log_msg("   Found verify_mode = 0: %d locations\n", foundVerify0);
    log_msg("   Successfully patched:  %d locations\n", patched);
    log_msg("=================================================\n");
    
    if (patched == foundVerify1) {
        log_msg("\n[+] SUCCESS! All verify_mode=1 locations patched\n");
    } else {
        log_msg("\n[-] WARNING: Not all locations patched\n");
    }
    
    // Verify patches
    log_msg("\n[*] Verifying patches...\n");
    
    SIZE_T bytesRead2;
    BYTE* verify = (BYTE*)malloc(dllSize);
    if (ReadProcessMemory(hProcess, dllBase, verify, dllSize, &bytesRead2)) {
        int stillHasVerify1 = 0;
        for (DWORD i = 0; i < bytesRead2 - 10; i++) {
            if (verify[i] == 0xC7 && 
                (verify[i+1] >= 0x80 && verify[i+1] <= 0x87) &&
                verify[i+2] == 0x30 && verify[i+3] == 0x01 &&
                verify[i+4] == 0x00 && verify[i+5] == 0x00 &&
                verify[i+6] == 0x01 &&
                verify[i+7] == 0x00 && verify[i+8] == 0x00 && verify[i+9] == 0x00) {
                log_msg("  [!] Still has verify=1 at +0x%05X\n", i);
                stillHasVerify1++;
            }
        }
        if (stillHasVerify1 == 0) {
            log_msg("[+] Verification complete: No verify_mode=1 remaining\n");
        } else {
            log_msg("[-] WARNING: %d verify_mode=1 still present\n", stillHasVerify1);
        }
        free(verify);
    }
    
    free(dllData);
    CloseHandle(hProcess);
    
    log_msg("\n[*] Patcher complete. Try connecting to server now.\n");
    log_msg("[*] Check %s for details\n", LOG_FILE);
    
    if (g_log) fclose(g_log);
    
    printf("\nPress Enter to exit...\n");
    getchar();
    return 0;
}
