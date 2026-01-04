/*
 * Dead Space 2 SSL Certificate Bypass Tool
 * 
 * Purpose:
 *   Disables SSL/TLS certificate validation in the activation DLL to allow
 *   connections to custom servers with self-signed certificates.
 *
 * How it works:
 *   The activation.x86.dll uses OpenSSL 1.0.0b with a verify callback function
 *   that validates server certificates during TLS handshake. This tool patches
 *   that callback to always return success (1), accepting any certificate.
 *
 * Technical Details:
 *   - Target: SSL verify callback in activation.x86.dll
 *   - Location: RVA 0x5EAC (file offset 0x52AC)
 *   - Original: push ebp; mov ebp,esp; sub esp,0x20; ...
 *   - Patched:  mov eax,1; ret (always return "certificate valid")
 *
 * The DLL is protected with Solidshield (Themida-based) packing, so we must:
 *   1. Wait for the game to start and load the DLL
 *   2. Wait for the DLL to unpack itself in memory
 *   3. Search for and patch the decrypted verify callback
 *
 * Build (MinGW cross-compile from Linux):
 *   i686-w64-mingw32-gcc -o ds2_ssl_bypass.exe ds2_ssl_bypass.c -lpsapi -Wall
 *
 * Build (MSVC on Windows):
 *   cl ds2_ssl_bypass.c /link psapi.lib
 *
 * Usage:
 *   1. Run this tool
 *   2. Start Dead Space 2
 *   3. Wait for "PATCH SUCCESSFUL" message
 *   4. Connect to your custom server
 *
 * Author: open-ds2-server project
 * License: MIT
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>
#include <psapi.h>

/* Configuration */
#define GAME_PROCESS_NAME   "deadspace2.exe"
#define TARGET_DLL_NAME     "activation.x86.dll"
#define WAIT_TIMEOUT_SEC    120
#define UNPACK_TIMEOUT_SEC  30

/*
 * SSL Verify Callback Signature
 * 
 * This is the entry point of the OpenSSL verify callback:
 * 
 *   int verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
 *       ...
 *   }
 *
 * Disassembly (11 bytes):
 *   55              push ebp
 *   8B EC           mov ebp, esp  
 *   83 EC 20        sub esp, 0x20
 *   A1 38 80 67 79  mov eax, [0x79678038]  ; __security_cookie
 */
static const BYTE VERIFY_CALLBACK_SIGNATURE[] = {
    0x55,                           /* push ebp                    */
    0x8B, 0xEC,                     /* mov ebp, esp                */
    0x83, 0xEC, 0x20,               /* sub esp, 0x20               */
    0xA1, 0x38, 0x80, 0x67, 0x79    /* mov eax, [__security_cookie]*/
};

/*
 * Bypass Patch
 * 
 * Replace the callback entry with code that immediately returns 1:
 *   B8 01 00 00 00  mov eax, 1    ; Return value = 1 (success)
 *   C3              ret           ; Return to caller
 *
 * In OpenSSL's verify callback protocol:
 *   - Return 1: Certificate is valid, continue handshake
 *   - Return 0: Certificate is invalid, abort connection
 */
static const BYTE BYPASS_PATCH[] = {
    0xB8, 0x01, 0x00, 0x00, 0x00,   /* mov eax, 1 */
    0xC3                            /* ret        */
};

/* Module information structure */
typedef struct {
    void*  base_address;
    size_t size;
} ModuleInfo;

/* Logging with timestamps */
static FILE* g_logfile = NULL;

static void log_init(void) {
    g_logfile = fopen("ds2_ssl_bypass.log", "w");
}

static void log_close(void) {
    if (g_logfile) {
        fclose(g_logfile);
        g_logfile = NULL;
    }
}

static void log_printf(const char* level, const char* fmt, ...) {
    SYSTEMTIME st;
    GetLocalTime(&st);
    
    char prefix[64];
    snprintf(prefix, sizeof(prefix), "[%02d:%02d:%02d] [%s] ",
             st.wHour, st.wMinute, st.wSecond, level);
    
    va_list args;
    va_start(args, fmt);
    
    /* Console output */
    printf("%s", prefix);
    vprintf(fmt, args);
    
    /* File output */
    if (g_logfile) {
        fprintf(g_logfile, "%s", prefix);
        va_start(args, fmt);
        vfprintf(g_logfile, fmt, args);
        fflush(g_logfile);
    }
    
    va_end(args);
}

#define LOG_INFO(...)  log_printf("INFO ", __VA_ARGS__)
#define LOG_WARN(...)  log_printf("WARN ", __VA_ARGS__)
#define LOG_ERROR(...) log_printf("ERROR", __VA_ARGS__)
#define LOG_OK(...)    log_printf(" OK  ", __VA_ARGS__)

/*
 * Find a process by name
 * Returns: Process ID or 0 if not found
 */
static DWORD find_process_by_name(const char* process_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(entry);
    
    DWORD pid = 0;
    if (Process32First(snapshot, &entry)) {
        do {
            if (_stricmp(entry.szExeFile, process_name) == 0) {
                pid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry));
    }
    
    CloseHandle(snapshot);
    return pid;
}

/*
 * Find a loaded module (DLL) in a process
 * Returns: 1 if found, 0 otherwise
 */
static int find_module_in_process(HANDLE process, const char* module_name, ModuleInfo* out_info) {
    HMODULE modules[1024];
    DWORD bytes_needed;
    
    if (!EnumProcessModules(process, modules, sizeof(modules), &bytes_needed)) {
        return 0;
    }
    
    int module_count = bytes_needed / sizeof(HMODULE);
    
    for (int i = 0; i < module_count; i++) {
        char full_path[MAX_PATH];
        if (GetModuleFileNameExA(process, modules[i], full_path, sizeof(full_path))) {
            /* Extract just the filename */
            const char* filename = strrchr(full_path, '\\');
            filename = filename ? filename + 1 : full_path;
            
            if (_stricmp(filename, module_name) == 0) {
                MODULEINFO mi;
                if (GetModuleInformation(process, modules[i], &mi, sizeof(mi))) {
                    out_info->base_address = mi.lpBaseOfDll;
                    out_info->size = mi.SizeOfImage;
                    return 1;
                }
            }
        }
    }
    
    return 0;
}

/*
 * Check if the DLL has been unpacked by Solidshield
 * 
 * The packer encrypts the .text section. When unpacked, valid x86 code appears.
 * We detect unpacking by looking for:
 *   - Function prologues (push ebp; mov ebp, esp)
 *   - NULL bytes (common in code, rare in encrypted data)
 */
static int is_dll_unpacked(HANDLE process, const ModuleInfo* module) {
    /* Read from .text section (starts at RVA 0x1000) */
    const size_t CHECK_SIZE = 4096;
    BYTE* buffer = malloc(CHECK_SIZE);
    if (!buffer) return 0;
    
    void* text_section = (BYTE*)module->base_address + 0x1000;
    SIZE_T bytes_read;
    
    if (!ReadProcessMemory(process, text_section, buffer, CHECK_SIZE, &bytes_read)) {
        free(buffer);
        return 0;
    }
    
    /* Count indicators of valid code */
    int null_count = 0;
    int prologue_count = 0;
    
    for (size_t i = 0; i < bytes_read; i++) {
        if (buffer[i] == 0x00) {
            null_count++;
        }
        /* Standard function prologue: 55 8B EC */
        if (i + 2 < bytes_read && 
            buffer[i] == 0x55 && 
            buffer[i+1] == 0x8B && 
            buffer[i+2] == 0xEC) {
            prologue_count++;
        }
    }
    
    free(buffer);
    
    /* Heuristic: decrypted code has >2% nulls and multiple prologues */
    int null_threshold = (int)(bytes_read * 0.02);
    int is_unpacked = (null_count > null_threshold) && (prologue_count >= 2);
    
    LOG_INFO("Unpack check: nulls=%d (need>%d), prologues=%d (need>=2) -> %s\n",
             null_count, null_threshold, prologue_count,
             is_unpacked ? "UNPACKED" : "encrypted");
    
    return is_unpacked;
}

/*
 * Search for the verify callback and apply the bypass patch
 * Returns: 1 on success, 0 on failure
 */
static int apply_certificate_bypass(HANDLE process, const ModuleInfo* module) {
    /* Allocate buffer for entire module */
    BYTE* buffer = malloc(module->size);
    if (!buffer) {
        LOG_ERROR("Failed to allocate %zu bytes for module scan\n", module->size);
        return 0;
    }
    
    /* Read module memory */
    SIZE_T bytes_read;
    if (!ReadProcessMemory(process, module->base_address, buffer, module->size, &bytes_read)) {
        LOG_ERROR("ReadProcessMemory failed (error %lu)\n", GetLastError());
        free(buffer);
        return 0;
    }
    
    LOG_INFO("Scanning %zu bytes for verify callback signature...\n", bytes_read);
    
    /* Search for the callback signature */
    void* patch_address = NULL;
    size_t found_offset = 0;
    
    for (size_t offset = 0; offset < bytes_read - sizeof(VERIFY_CALLBACK_SIGNATURE); offset++) {
        if (memcmp(buffer + offset, VERIFY_CALLBACK_SIGNATURE, sizeof(VERIFY_CALLBACK_SIGNATURE)) == 0) {
            patch_address = (BYTE*)module->base_address + offset;
            found_offset = offset;
            LOG_OK("Found verify callback at RVA 0x%zX (VA 0x%p)\n", offset, patch_address);
            break;
        }
    }
    
    free(buffer);
    
    if (!patch_address) {
        LOG_ERROR("Verify callback signature not found\n");
        return 0;
    }
    
    /* Verify the location is reasonable (should be around RVA 0x5EAC) */
    if (found_offset < 0x1000 || found_offset > 0x100000) {
        LOG_WARN("Found at unexpected RVA 0x%zX (expected near 0x5EAC)\n", found_offset);
    }
    
    /* Make the memory writable */
    DWORD old_protection;
    if (!VirtualProtectEx(process, patch_address, sizeof(BYPASS_PATCH), 
                          PAGE_EXECUTE_READWRITE, &old_protection)) {
        LOG_ERROR("VirtualProtectEx failed (error %lu)\n", GetLastError());
        return 0;
    }
    
    /* Write the bypass patch */
    SIZE_T bytes_written;
    BOOL write_ok = WriteProcessMemory(process, patch_address, BYPASS_PATCH, 
                                        sizeof(BYPASS_PATCH), &bytes_written);
    
    /* Restore original protection */
    VirtualProtectEx(process, patch_address, sizeof(BYPASS_PATCH), old_protection, &old_protection);
    
    if (!write_ok) {
        LOG_ERROR("WriteProcessMemory failed (error %lu)\n", GetLastError());
        return 0;
    }
    
    LOG_OK("Wrote %zu bytes: verify callback now returns 1 (accept all)\n", bytes_written);
    return 1;
}

/*
 * Wait for a process to start
 */
static DWORD wait_for_process(const char* name, int timeout_sec) {
    LOG_INFO("Waiting for %s to start...\n", name);
    
    for (int elapsed = 0; elapsed < timeout_sec; elapsed++) {
        DWORD pid = find_process_by_name(name);
        if (pid != 0) {
            LOG_OK("Found %s (PID %lu)\n", name, pid);
            return pid;
        }
        
        Sleep(1000);
        
        if (elapsed > 0 && elapsed % 15 == 0) {
            LOG_INFO("Still waiting... (%d/%d seconds)\n", elapsed, timeout_sec);
        }
    }
    
    LOG_ERROR("Timeout waiting for %s (%d seconds)\n", name, timeout_sec);
    return 0;
}

/*
 * Wait for a module to load in a process
 */
static int wait_for_module(HANDLE process, const char* name, ModuleInfo* out_info, int timeout_sec) {
    LOG_INFO("Waiting for %s to load...\n", name);
    
    for (int elapsed = 0; elapsed < timeout_sec; elapsed++) {
        if (find_module_in_process(process, name, out_info)) {
            LOG_OK("Found %s at 0x%p (%zu bytes)\n", name, out_info->base_address, out_info->size);
            return 1;
        }
        Sleep(1000);
    }
    
    LOG_ERROR("Timeout waiting for %s (%d seconds)\n", name, timeout_sec);
    return 0;
}

/*
 * Wait for DLL unpacking to complete
 */
static int wait_for_unpack(HANDLE process, const ModuleInfo* module, int timeout_sec) {
    LOG_INFO("Waiting for DLL to unpack (Solidshield protection)...\n");
    
    for (int elapsed = 0; elapsed < timeout_sec; elapsed++) {
        if (is_dll_unpacked(process, module)) {
            LOG_OK("DLL unpacking detected\n");
            /* Give it a moment to finish completely */
            Sleep(2000);
            return 1;
        }
        Sleep(1000);
    }
    
    LOG_WARN("DLL may not have fully unpacked (timeout %d sec)\n", timeout_sec);
    return 0;  /* Continue anyway, patch might still work */
}

static void print_banner(void) {
    printf("\n");
    printf("  =====================================================\n");
    printf("  Dead Space 2 - SSL Certificate Bypass Tool\n");
    printf("  =====================================================\n");
    printf("  Patches the activation DLL to accept any certificate,\n");
    printf("  enabling connections to custom multiplayer servers.\n");
    printf("  =====================================================\n");
    printf("\n");
}

static void print_result(int success) {
    printf("\n");
    if (success) {
        printf("  +-------------------------------------------+\n");
        printf("  |         CERTIFICATE BYPASS ACTIVE        |\n");
        printf("  +-------------------------------------------+\n");
        printf("  | The game will now accept self-signed     |\n");
        printf("  | certificates from custom servers.        |\n");
        printf("  |                                          |\n");
        printf("  | You can now connect to your server!      |\n");
        printf("  +-------------------------------------------+\n");
    } else {
        printf("  +-------------------------------------------+\n");
        printf("  |            BYPASS FAILED                 |\n");
        printf("  +-------------------------------------------+\n");
        printf("  | Could not patch the verify callback.     |\n");
        printf("  |                                          |\n");
        printf("  | Possible causes:                         |\n");
        printf("  | - Different game version                 |\n");
        printf("  | - DLL protection changed                 |\n");
        printf("  | - Antivirus interference                 |\n");
        printf("  +-------------------------------------------+\n");
    }
    printf("\n");
}

int main(int argc, char* argv[]) {
    print_banner();
    log_init();
    
    LOG_INFO("Dead Space 2 SSL Certificate Bypass starting...\n");
    LOG_INFO("Target: %s -> %s\n", GAME_PROCESS_NAME, TARGET_DLL_NAME);
    LOG_INFO("Callback RVA: 0x5EAC, Patch: mov eax,1; ret\n\n");
    
    /* Step 1: Wait for game process */
    DWORD pid = wait_for_process(GAME_PROCESS_NAME, WAIT_TIMEOUT_SEC);
    if (pid == 0) {
        print_result(0);
        log_close();
        printf("Press Enter to exit...\n");
        getchar();
        return 1;
    }
    
    /* Step 2: Open process with required permissions */
    HANDLE process = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    
    if (!process) {
        LOG_ERROR("Cannot open process (error %lu) - try running as Administrator\n", GetLastError());
        print_result(0);
        log_close();
        printf("Press Enter to exit...\n");
        getchar();
        return 1;
    }
    
    /* Step 3: Wait for activation DLL to load */
    ModuleInfo module = {0};
    if (!wait_for_module(process, TARGET_DLL_NAME, &module, 60)) {
        CloseHandle(process);
        print_result(0);
        log_close();
        printf("Press Enter to exit...\n");
        getchar();
        return 1;
    }
    
    /* Step 4: Wait for DLL to unpack */
    wait_for_unpack(process, &module, UNPACK_TIMEOUT_SEC);
    
    /* Step 5: Apply the certificate bypass patch */
    LOG_INFO("Applying certificate bypass...\n");
    
    int success = 0;
    for (int attempt = 1; attempt <= 3; attempt++) {
        LOG_INFO("Patch attempt %d/3\n", attempt);
        
        if (apply_certificate_bypass(process, &module)) {
            success = 1;
            break;
        }
        
        if (attempt < 3) {
            LOG_INFO("Waiting 2 seconds before retry...\n");
            Sleep(2000);
        }
    }
    
    CloseHandle(process);
    print_result(success);
    log_close();
    
    printf("Press Enter to exit...\n");
    getchar();
    
    return success ? 0 : 1;
}
