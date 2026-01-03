/*
 * Dead Space 2 Full SSL Patcher
 * 
 * This patcher does BOTH:
 * 1. Patches the code that sets verify_mode=1 (for future SSL contexts)
 * 2. Searches memory for existing SSL_CTX/SSL structures and patches their verify_mode field
 * 
 * The SSL_CTX structure has verify_mode at offset +0x130
 * We search for structures that have verify_mode=1 and change it to 0
 */

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#define GAME_EXE "deadspace2.exe"
#define TARGET_DLL "activation.x86.dll"
#define LOG_FILE "ds2_full_patcher.log"

FILE* g_log = NULL;

void log_msg(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    char buf[1024];
    vsnprintf(buf, sizeof(buf), fmt, args);
    printf("%s", buf);
    if (g_log) { fprintf(g_log, "%s", buf); fflush(g_log); }
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
    if (!EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) return NULL;
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

int patch_verify_mode_code(HANDLE hProcess, BYTE* dllBase, BYTE* dllData, SIZE_T dllSize) {
    int patched = 0;
    
    log_msg("\n[*] Phase 1: Patching verify_mode=1 instructions...\n");
    
    for (DWORD i = 0; i < dllSize - 10; i++) {
        // C7 8x 30 01 00 00 01 00 00 00 = mov [reg+0x130], 1
        if (dllData[i] == 0xC7 && 
            (dllData[i+1] >= 0x80 && dllData[i+1] <= 0x87) &&
            dllData[i+2] == 0x30 && dllData[i+3] == 0x01 &&
            dllData[i+4] == 0x00 && dllData[i+5] == 0x00 &&
            dllData[i+6] == 0x01 &&
            dllData[i+7] == 0x00 && dllData[i+8] == 0x00 && dllData[i+9] == 0x00) {
            
            log_msg("    [CODE] +0x%05X: mov [reg+0x130], 1\n", i);
            
            DWORD oldProtect;
            BYTE zero = 0;
            if (VirtualProtectEx(hProcess, dllBase + i + 6, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                SIZE_T written;
                if (WriteProcessMemory(hProcess, dllBase + i + 6, &zero, 1, &written)) {
                    FlushInstructionCache(hProcess, dllBase + i + 6, 1);
                    dllData[i + 6] = 0;
                    log_msg("            -> Patched to 0!\n");
                    patched++;
                }
                VirtualProtectEx(hProcess, dllBase + i + 6, 1, oldProtect, &oldProtect);
            }
        }
    }
    
    return patched;
}

int patch_ssl_ctx_structures(HANDLE hProcess, BYTE* dllBase, BYTE* dllData, SIZE_T dllSize) {
    int patched = 0;
    
    log_msg("\n[*] Phase 2: Searching for SSL_CTX structures with verify_mode=1...\n");
    
    /*
     * SSL_CTX structure identification:
     * - offset 0x130: verify_mode (should be 0 or 1)
     * - offset 0x134: verify_callback (pointer or NULL)
     * - We look for memory patterns that match SSL_CTX layout
     * 
     * A valid SSL_CTX typically has:
     * - References to method table at offset 0
     * - Various pointers and integers
     * - verify_mode at +0x130
     * 
     * We search the heap regions for structures with verify_mode=1
     */
    
    // Search the DLL's data sections for SSL_CTX structures
    // SSL_CTX structures are typically allocated on the heap, but might have
    // pointers to them in the DLL's data section
    
    // Let's search for DWORD value 1 at positions where it could be verify_mode
    // and the surrounding context looks like SSL_CTX
    
    for (DWORD i = 0; i < dllSize - 0x140; i++) {
        // Check if this could be verify_mode=1 in an SSL_CTX
        // We look at offset i as if it's the start of an SSL_CTX
        // and check if [i+0x130] == 1
        
        DWORD* verify_mode_ptr = (DWORD*)(dllData + i + 0x130);
        if (*verify_mode_ptr == 1) {
            // Check if this looks like a valid SSL_CTX
            // The first field should be a method pointer (within valid address range)
            DWORD first_field = *(DWORD*)(dllData + i);
            
            // Method pointer should look like a valid address in the DLL
            // or a heap pointer (0x00xxxxxx or 0x7xxxxxxx)
            if ((first_field >= (DWORD)dllBase && first_field < (DWORD)dllBase + dllSize) ||
                (first_field >= 0x00100000 && first_field < 0x80000000)) {
                
                // Additional check: verify_callback at +0x134 should be 0 or a valid pointer
                DWORD callback = *(DWORD*)(dllData + i + 0x134);
                if (callback == 0 || (callback >= 0x00100000 && callback < 0x80000000)) {
                    
                    log_msg("    [CTX?] +0x%05X: Potential SSL_CTX with verify_mode=1\n", i);
                    log_msg("            method=0x%08X, callback=0x%08X\n", first_field, callback);
                    
                    // Patch it
                    DWORD oldProtect;
                    DWORD zero = 0;
                    if (VirtualProtectEx(hProcess, dllBase + i + 0x130, 4, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                        SIZE_T written;
                        if (WriteProcessMemory(hProcess, dllBase + i + 0x130, &zero, 4, &written)) {
                            *verify_mode_ptr = 0;
                            log_msg("            -> Patched verify_mode to 0!\n");
                            patched++;
                        }
                        VirtualProtectEx(hProcess, dllBase + i + 0x130, 4, oldProtect, &oldProtect);
                    }
                }
            }
        }
    }
    
    return patched;
}

int patch_heap_ssl_contexts(HANDLE hProcess) {
    int patched = 0;
    
    log_msg("\n[*] Phase 3: Searching heap for SSL_CTX structures...\n");
    
    // Enumerate memory regions
    MEMORY_BASIC_INFORMATION mbi;
    BYTE* addr = NULL;
    
    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && 
            (mbi.Protect == PAGE_READWRITE || mbi.Protect == PAGE_EXECUTE_READWRITE) &&
            mbi.RegionSize >= 0x140) {
            
            // Read this region
            BYTE* regionData = (BYTE*)malloc(mbi.RegionSize);
            SIZE_T bytesRead;
            
            if (regionData && ReadProcessMemory(hProcess, mbi.BaseAddress, regionData, mbi.RegionSize, &bytesRead)) {
                // Search for SSL_CTX structures
                for (SIZE_T i = 0; i + 0x140 <= bytesRead; i += 4) {
                    DWORD* verify_mode_ptr = (DWORD*)(regionData + i + 0x130);
                    
                    if (*verify_mode_ptr == 1) {
                        // Check surrounding context
                        DWORD first_field = *(DWORD*)(regionData + i);
                        DWORD callback = *(DWORD*)(regionData + i + 0x134);
                        
                        if ((first_field >= 0x00100000 && first_field < 0x80000000) &&
                            (callback == 0 || (callback >= 0x00100000 && callback < 0x80000000))) {
                            
                            log_msg("    [HEAP] 0x%p+0x%X: Potential SSL_CTX\n", mbi.BaseAddress, (DWORD)i);
                            
                            // Patch it
                            DWORD zero = 0;
                            DWORD oldProtect;
                            BYTE* target = (BYTE*)mbi.BaseAddress + i + 0x130;
                            
                            if (VirtualProtectEx(hProcess, target, 4, PAGE_READWRITE, &oldProtect)) {
                                SIZE_T written;
                                if (WriteProcessMemory(hProcess, target, &zero, 4, &written)) {
                                    log_msg("            -> Patched!\n");
                                    patched++;
                                }
                                VirtualProtectEx(hProcess, target, 4, oldProtect, &oldProtect);
                            }
                        }
                    }
                }
            }
            
            if (regionData) free(regionData);
        }
        
        addr = (BYTE*)mbi.BaseAddress + mbi.RegionSize;
    }
    
    return patched;
}

int main() {
    g_log = fopen(LOG_FILE, "w");
    
    time_t now = time(NULL);
    log_msg("=================================================\n");
    log_msg(" Dead Space 2 Full SSL Patcher\n");
    log_msg(" Started: %s", ctime(&now));
    log_msg("=================================================\n\n");
    
    log_msg("[*] Looking for %s...\n", GAME_EXE);
    
    DWORD pid = 0;
    for (int i = 0; i < 120 && !pid; i++) {
        pid = FindProcess(GAME_EXE);
        if (!pid) { Sleep(1000); if (i % 10 == 0) log_msg("    Waiting... (%d seconds)\n", i); }
    }
    
    if (!pid) {
        log_msg("[-] Game not found\n");
        if (g_log) fclose(g_log);
        return 1;
    }
    
    log_msg("[+] Found game: PID %lu\n", pid);
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        log_msg("[-] Failed to open process\n");
        if (g_log) fclose(g_log);
        return 1;
    }
    
    BYTE* dllBase = NULL;
    DWORD dllSize = 0;
    
    log_msg("[*] Waiting for %s...\n", TARGET_DLL);
    for (int i = 0; i < 60 && !dllBase; i++) {
        dllBase = FindModuleBase(hProcess, TARGET_DLL, &dllSize);
        if (!dllBase) { Sleep(1000); if (i % 10 == 0) log_msg("    Waiting... (%d seconds)\n", i); }
    }
    
    if (!dllBase) {
        log_msg("[-] DLL not found\n");
        CloseHandle(hProcess);
        if (g_log) fclose(g_log);
        return 1;
    }
    
    log_msg("[+] Found %s at 0x%p (size: %lu)\n", TARGET_DLL, dllBase, dllSize);
    
    log_msg("[*] Waiting 5 seconds for Themida unpacking...\n");
    Sleep(5000);
    
    log_msg("[*] Reading DLL memory...\n");
    BYTE* dllData = (BYTE*)malloc(dllSize);
    SIZE_T bytesRead = 0;
    
    if (!ReadProcessMemory(hProcess, dllBase, dllData, dllSize, &bytesRead)) {
        log_msg("[-] Failed to read DLL memory\n");
        free(dllData);
        CloseHandle(hProcess);
        if (g_log) fclose(g_log);
        return 1;
    }
    
    log_msg("[+] Read %zu bytes\n", bytesRead);
    
    int total = 0;
    
    // Phase 1: Patch code
    total += patch_verify_mode_code(hProcess, dllBase, dllData, bytesRead);
    
    // Phase 2: Patch DLL data section SSL_CTX structures
    total += patch_ssl_ctx_structures(hProcess, dllBase, dllData, bytesRead);
    
    // Phase 3: Patch heap SSL_CTX structures
    total += patch_heap_ssl_contexts(hProcess);
    
    log_msg("\n=================================================\n");
    log_msg(" Total patches applied: %d\n", total);
    log_msg("=================================================\n");
    
    free(dllData);
    CloseHandle(hProcess);
    
    log_msg("\n[*] Patcher complete. Try connecting NOW.\n");
    
    if (g_log) fclose(g_log);
    
    printf("\nPress Enter to exit...\n");
    getchar();
    return 0;
}
