/*
 * Dead Space 2 SSL Patcher v11 - Verified Callback Patch
 * 
 * Based on complete reverse engineering of activation_decrypted.dll.
 * This patches the SSL verification callback at the correct location.
 *
 * Callback Analysis:
 *   - File offset: 0x52AC  
 *   - RVA: 0x5EAC
 *   - VA: 0x79655EAC (with image base 0x79650000)
 *   - Function: SSL_CTX_set_verify callback
 *
 * The callback is called during TLS handshake. Returning 1 = accept certificate.
 *
 * Build:
 *   i686-w64-mingw32-gcc -o ds2_ssl_patcher_v11.exe ds2_ssl_patcher_v11.c -lpsapi
 *
 * Usage:
 *   1. Start Dead Space 2
 *   2. Run this patcher (it will wait for the DLL to unpack)
 *   3. The patch will be applied automatically
 */

#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <psapi.h>

#define TARGET_PROCESS "deadspace2.exe"
#define TARGET_DLL "activation.x86.dll"

// SSL verify callback pattern - first 11 bytes of the function
// This pattern is unique and identifies the callback entry point
static const unsigned char CALLBACK_PATTERN[] = {
    0x55,                         // push ebp
    0x8B, 0xEC,                   // mov ebp, esp
    0x83, 0xEC, 0x20,             // sub esp, 0x20
    0xA1, 0x38, 0x80, 0x67, 0x79  // mov eax, [0x79678038] (__security_cookie)
};
#define PATTERN_LEN sizeof(CALLBACK_PATTERN)

// Patch bytes: mov eax, 1; ret
// This makes the callback immediately return 1 (accept any certificate)
static const unsigned char PATCH_BYTES[] = {
    0xB8, 0x01, 0x00, 0x00, 0x00,  // mov eax, 1
    0xC3                           // ret
};
#define PATCH_LEN sizeof(PATCH_BYTES)

static FILE* logfile = NULL;

void log_msg(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    
    char timestamp[32];
    SYSTEMTIME st;
    GetLocalTime(&st);
    snprintf(timestamp, sizeof(timestamp), "[%02d:%02d:%02d.%03d] ", 
             st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    
    if (!logfile) {
        logfile = fopen("ds2_ssl_patcher_v11.log", "w");
    }
    if (logfile) {
        fputs(timestamp, logfile);
        vfprintf(logfile, fmt, args);
        fflush(logfile);
    }
    printf("%s", timestamp);
    vprintf(fmt, args);
    va_end(args);
}

DWORD find_process(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    DWORD pid = 0;
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    
    CloseHandle(snap);
    return pid;
}

typedef struct {
    LPVOID base;
    SIZE_T size;
} ModuleInfo;

int find_module(HANDLE hProcess, const char* name, ModuleInfo* info) {
    HMODULE modules[1024];
    DWORD needed;
    
    if (!EnumProcessModules(hProcess, modules, sizeof(modules), &needed)) {
        return 0;
    }
    
    int count = needed / sizeof(HMODULE);
    for (int i = 0; i < count; i++) {
        char modName[MAX_PATH];
        if (GetModuleFileNameExA(hProcess, modules[i], modName, MAX_PATH)) {
            char* baseName = strrchr(modName, '\\');
            if (baseName) baseName++; else baseName = modName;
            
            if (_stricmp(baseName, name) == 0) {
                MODULEINFO mi;
                if (GetModuleInformation(hProcess, modules[i], &mi, sizeof(mi))) {
                    info->base = mi.lpBaseOfDll;
                    info->size = mi.SizeOfImage;
                    return 1;
                }
            }
        }
    }
    return 0;
}

// Check if the DLL appears to be unpacked by looking for decrypted code patterns
int check_if_unpacked(HANDLE hProcess, ModuleInfo* module) {
    // Read the first few KB of the .text section (starts at RVA 0x1000)
    unsigned char buf[4096];
    SIZE_T bytesRead;
    LPVOID textSection = (LPVOID)((unsigned char*)module->base + 0x1000);
    
    if (!ReadProcessMemory(hProcess, textSection, buf, sizeof(buf), &bytesRead)) {
        return 0;
    }
    
    // Encrypted code has very high entropy (looks random)
    // Decrypted x86 code has common patterns like 0x00, 0xFF, function prologues
    int zero_count = 0;
    int prologue_count = 0;
    
    for (SIZE_T i = 0; i < bytesRead - 2; i++) {
        if (buf[i] == 0x00) zero_count++;
        if (buf[i] == 0x55 && buf[i+1] == 0x8B && buf[i+2] == 0xEC) prologue_count++;
    }
    
    // Decrypted code typically has >5% zeros and multiple function prologues
    int looks_decrypted = (zero_count > bytesRead / 20) && (prologue_count >= 2);
    
    log_msg("Unpacking check: zeros=%d/%zu, prologues=%d -> %s\n",
            zero_count, bytesRead, prologue_count,
            looks_decrypted ? "UNPACKED" : "still packed");
    
    return looks_decrypted;
}

int search_and_patch(HANDLE hProcess, ModuleInfo* module) {
    unsigned char* buffer = (unsigned char*)malloc(module->size);
    if (!buffer) {
        log_msg("ERROR: Failed to allocate %zu bytes\n", module->size);
        return 0;
    }
    
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, module->base, buffer, module->size, &bytesRead)) {
        log_msg("ERROR: ReadProcessMemory failed: %d\n", GetLastError());
        free(buffer);
        return 0;
    }
    
    log_msg("Read %zu bytes from module at 0x%p\n", bytesRead, module->base);
    
    // Search for the callback pattern
    LPVOID patch_addr = NULL;
    
    for (SIZE_T i = 0; i < bytesRead - PATTERN_LEN; i++) {
        if (memcmp(buffer + i, CALLBACK_PATTERN, PATTERN_LEN) == 0) {
            patch_addr = (LPVOID)((unsigned char*)module->base + i);
            log_msg("FOUND callback pattern at offset 0x%zX (VA: 0x%p)\n", i, patch_addr);
            break;
        }
    }
    
    free(buffer);
    
    if (!patch_addr) {
        log_msg("Pattern not found in module memory\n");
        return 0;
    }
    
    // Verify we're at the expected RVA
    SIZE_T found_rva = (SIZE_T)((unsigned char*)patch_addr - (unsigned char*)module->base);
    log_msg("Found at RVA 0x%zX (expected ~0x5EAC)\n", found_rva);
    
    // Apply the patch
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, patch_addr, PATCH_LEN, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        log_msg("ERROR: VirtualProtectEx failed: %d\n", GetLastError());
        return 0;
    }
    
    SIZE_T bytesWritten;
    if (!WriteProcessMemory(hProcess, patch_addr, PATCH_BYTES, PATCH_LEN, &bytesWritten)) {
        log_msg("ERROR: WriteProcessMemory failed: %d\n", GetLastError());
        VirtualProtectEx(hProcess, patch_addr, PATCH_LEN, oldProtect, &oldProtect);
        return 0;
    }
    
    // Restore original protection
    VirtualProtectEx(hProcess, patch_addr, PATCH_LEN, oldProtect, &oldProtect);
    
    log_msg("SUCCESS: Patched %zu bytes at 0x%p\n", bytesWritten, patch_addr);
    log_msg("SSL verify callback now returns 1 (accept all certificates)\n");
    
    return 1;
}

int main(int argc, char* argv[]) {
    log_msg("=== Dead Space 2 SSL Patcher v11 ===\n");
    log_msg("Based on reverse engineering of SSL verify callback\n");
    log_msg("Callback location: File 0x52AC, RVA 0x5EAC, VA 0x79655EAC\n\n");
    
    // Wait for game process
    log_msg("Waiting for %s...\n", TARGET_PROCESS);
    
    DWORD pid = 0;
    int wait_secs = 0;
    while ((pid = find_process(TARGET_PROCESS)) == 0) {
        Sleep(1000);
        wait_secs++;
        if (wait_secs % 10 == 0) {
            log_msg("Still waiting... (%d seconds)\n", wait_secs);
        }
        if (wait_secs > 120) {
            log_msg("ERROR: Timeout waiting for game (2 minutes)\n");
            return 1;
        }
    }
    
    log_msg("Found %s (PID: %d)\n", TARGET_PROCESS, pid);
    
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    
    if (!hProcess) {
        log_msg("ERROR: OpenProcess failed: %d\n", GetLastError());
        return 1;
    }
    
    // Wait for DLL to load
    log_msg("Waiting for %s...\n", TARGET_DLL);
    
    ModuleInfo module = {0};
    wait_secs = 0;
    while (!find_module(hProcess, TARGET_DLL, &module)) {
        Sleep(1000);
        wait_secs++;
        if (wait_secs > 60) {
            log_msg("ERROR: Timeout waiting for DLL (60 seconds)\n");
            CloseHandle(hProcess);
            return 1;
        }
    }
    
    log_msg("Found %s at 0x%p (size: %zu bytes)\n", TARGET_DLL, module.base, module.size);
    
    // Wait for DLL to unpack itself
    log_msg("Waiting for DLL to unpack...\n");
    
    int unpack_wait = 0;
    while (!check_if_unpacked(hProcess, &module)) {
        Sleep(1000);
        unpack_wait++;
        if (unpack_wait > 30) {
            log_msg("WARNING: DLL may not have unpacked after 30 seconds\n");
            break;
        }
    }
    
    // Additional wait to ensure unpacking is complete
    log_msg("Waiting additional 3 seconds for unpacking to complete...\n");
    Sleep(3000);
    
    // Attempt to patch
    int success = 0;
    for (int attempt = 1; attempt <= 3; attempt++) {
        log_msg("\n=== Patch attempt %d/3 ===\n", attempt);
        
        if (search_and_patch(hProcess, &module)) {
            success = 1;
            break;
        }
        
        if (attempt < 3) {
            log_msg("Retrying in 2 seconds...\n");
            Sleep(2000);
        }
    }
    
    CloseHandle(hProcess);
    
    log_msg("\n");
    if (success) {
        log_msg("========================================\n");
        log_msg("=        PATCH SUCCESSFUL!            =\n");
        log_msg("========================================\n");
        log_msg("The game will now accept self-signed certificates.\n");
        log_msg("You can connect to custom servers.\n");
    } else {
        log_msg("========================================\n");
        log_msg("=          PATCH FAILED               =\n");
        log_msg("========================================\n");
        log_msg("Could not find the SSL callback pattern.\n");
        log_msg("Possible causes:\n");
        log_msg("  - DLL did not fully unpack\n");
        log_msg("  - Game version uses different code\n");
        log_msg("  - Protection scheme changed\n");
    }
    
    if (logfile) fclose(logfile);
    
    log_msg("\nPress Enter to exit...\n");
    getchar();
    
    return success ? 0 : 1;
}
