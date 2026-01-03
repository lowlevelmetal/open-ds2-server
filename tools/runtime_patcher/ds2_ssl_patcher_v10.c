/*
 * Dead Space 2 SSL Patcher v10
 * 
 * Key insight from packet capture:
 * - Client uses SSLv3 ONLY (version 0x0300)
 * - Client only offers RC4 ciphers: TLS_RSA_WITH_RC4_128_SHA (0x0005), TLS_RSA_WITH_RC4_128_MD5 (0x0004)
 * - Client receives certificate, waits 31ms, then closes connection
 * - This indicates application-level certificate verification rejection
 *
 * Strategy: Patch the verify callback return value OR the result checking code
 * In OpenSSL, SSL_CTX_set_verify takes a callback that returns 1 for success.
 * We need to find where this callback result is checked.
 */

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>

#define TARGET_DLL "activation.x86.dll"

static FILE* logfile = NULL;

void log_msg(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    
    if (!logfile) {
        logfile = fopen("ds2_patcher_v10.log", "w");
    }
    if (logfile) {
        vfprintf(logfile, fmt, args);
        fflush(logfile);
    }
    vprintf(fmt, args);
    va_end(args);
}

/*
 * In OpenSSL, the verify callback is called from ssl3_get_server_certificate().
 * The callback returns 1 (success) or 0 (failure).
 * 
 * The typical pattern in assembly after calling verify callback:
 *   call [verify_callback]
 *   test eax, eax       ; Check if callback returned 0
 *   je   failure_path   ; Jump if zero (failure)
 * 
 * We want to change this to:
 *   call [verify_callback]
 *   mov eax, 1          ; Force success (B8 01 00 00 00)
 *   nop                 ; Pad to keep alignment
 *   ...
 * 
 * OR change the callback to always return 1.
 */

typedef struct {
    unsigned char* base;
    DWORD size;
    DWORD image_base;
} ModuleInfo;

ModuleInfo g_module = {0};

int find_module(const char* dll_name) {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, GetCurrentProcessId());
    if (hSnap == INVALID_HANDLE_VALUE) {
        return 0;
    }
    
    MODULEENTRY32 me;
    me.dwSize = sizeof(me);
    
    if (Module32First(hSnap, &me)) {
        do {
            if (_stricmp(me.szModule, dll_name) == 0) {
                g_module.base = me.modBaseAddr;
                g_module.size = me.modBaseSize;
                log_msg("Found %s at 0x%p, size %u bytes\n", dll_name, me.modBaseAddr, me.modBaseSize);
                CloseHandle(hSnap);
                return 1;
            }
        } while (Module32Next(hSnap, &me));
    }
    
    CloseHandle(hSnap);
    return 0;
}

// Pattern 1: Patch verify callback result check
// Looking for: test eax, eax; jz/je xxx
// Change to:   mov eax, 1; nop; nop; nop
int patch_callback_result_checks() {
    int patches = 0;
    
    // Find sequences where callback result is checked and failure path taken
    // Pattern: 85 C0 (test eax,eax) followed by 0F 84 (je) or 74 (je short)
    for (DWORD i = 0; i < g_module.size - 10; i++) {
        // test eax,eax; je near
        if (g_module.base[i] == 0x85 && 
            g_module.base[i+1] == 0xC0 &&
            g_module.base[i+2] == 0x0F &&
            g_module.base[i+3] == 0x84) {
            
            // Check context - look for call instruction before (E8 or FF 15/55)
            int has_call = 0;
            for (int j = 1; j < 20; j++) {
                if (i >= j && g_module.base[i-j] == 0xE8) {
                    has_call = 1;
                    break;
                }
                if (i >= j+1 && g_module.base[i-j-1] == 0xFF && 
                    (g_module.base[i-j] == 0x15 || g_module.base[i-j] == 0x55 || g_module.base[i-j] == 0xD0)) {
                    has_call = 1;
                    break;
                }
            }
            
            if (has_call) {
                DWORD offset = (DWORD)(g_module.base + i - g_module.base);
                log_msg("Pattern 1 at +0x%X: test eax,eax; je near (after call)\n", offset);
                
                // Change: test eax,eax; 0F 84 xx xx xx xx
                // To:     mov eax,1; nop; nop; nop; nop; nop
                DWORD old_protect;
                if (VirtualProtect(g_module.base + i, 8, PAGE_EXECUTE_READWRITE, &old_protect)) {
                    g_module.base[i] = 0xB8;      // mov eax,
                    g_module.base[i+1] = 0x01;    // 1
                    g_module.base[i+2] = 0x00;
                    g_module.base[i+3] = 0x00;
                    g_module.base[i+4] = 0x00;
                    g_module.base[i+5] = 0x90;    // nop
                    g_module.base[i+6] = 0x90;    // nop
                    g_module.base[i+7] = 0x90;    // nop
                    VirtualProtect(g_module.base + i, 8, old_protect, &old_protect);
                    patches++;
                }
            }
        }
        
        // test eax,eax; je short  
        if (g_module.base[i] == 0x85 && 
            g_module.base[i+1] == 0xC0 &&
            g_module.base[i+2] == 0x74) {
            
            // Check context - look for call instruction before
            int has_call = 0;
            for (int j = 1; j < 20; j++) {
                if (i >= j && g_module.base[i-j] == 0xE8) {
                    has_call = 1;
                    break;
                }
                if (i >= j+1 && g_module.base[i-j-1] == 0xFF && 
                    (g_module.base[i-j] == 0x15 || g_module.base[i-j] == 0x55 || g_module.base[i-j] == 0xD0)) {
                    has_call = 1;
                    break;
                }
            }
            
            if (has_call) {
                DWORD offset = (DWORD)(g_module.base + i - g_module.base);
                log_msg("Pattern 1s at +0x%X: test eax,eax; je short (after call)\n", offset);
                
                // Change: test eax,eax; 74 xx
                // To:     mov eax,1; nop
                DWORD old_protect;
                if (VirtualProtect(g_module.base + i, 4, PAGE_EXECUTE_READWRITE, &old_protect)) {
                    g_module.base[i] = 0xB8;      // mov eax,
                    g_module.base[i+1] = 0x01;    // 1
                    g_module.base[i+2] = 0x00;
                    g_module.base[i+3] = 0x00;
                    // We're overwriting the jump offset byte, need to be careful
                    // Actually just nop the je instruction
                    g_module.base[i] = 0x85;      // keep test eax,eax
                    g_module.base[i+1] = 0xC0;
                    g_module.base[i+2] = 0x90;    // nop (was 74)
                    g_module.base[i+3] = 0x90;    // nop (was offset)
                    VirtualProtect(g_module.base + i, 4, old_protect, &old_protect);
                    patches++;
                }
            }
        }
    }
    
    return patches;
}

// Pattern 2: Find SSL_CTX_set_verify calls and patch the mode argument
// In OpenSSL: SSL_CTX_set_verify(ctx, mode, callback)
// mode=0 means no verification, mode=1 means verify peer
// We want to change the push 1 before call to push 0
int patch_set_verify_calls() {
    int patches = 0;
    
    // The existing v8 patcher targets these but let's verify they're applied
    // Known offsets from analysis:
    // +0xB1FF: C7 44 24 64 01 00 00 00  (mov dword ptr [esp+64h], 1)
    // +0xB6FC: C7 44 24 64 01 00 00 00
    // +0xCB08: C7 44 24 64 01 00 00 00
    
    unsigned char expected[] = {0xC7, 0x44, 0x24, 0x64, 0x01, 0x00, 0x00, 0x00};
    unsigned char patched[]  = {0xC7, 0x44, 0x24, 0x64, 0x00, 0x00, 0x00, 0x00};
    
    DWORD offsets[] = {0xB1FF, 0xB6FC, 0xCB08};
    
    for (int i = 0; i < 3; i++) {
        if (offsets[i] >= g_module.size) continue;
        
        unsigned char* addr = g_module.base + offsets[i];
        
        if (memcmp(addr, expected, 8) == 0) {
            log_msg("verify_mode location at +0x%X needs patching\n", offsets[i]);
            DWORD old_protect;
            if (VirtualProtect(addr, 8, PAGE_EXECUTE_READWRITE, &old_protect)) {
                memcpy(addr, patched, 8);
                VirtualProtect(addr, 8, old_protect, &old_protect);
                patches++;
            }
        } else if (memcmp(addr, patched, 8) == 0) {
            log_msg("verify_mode location at +0x%X already patched\n", offsets[i]);
        } else {
            log_msg("verify_mode location at +0x%X: unexpected content: %02X %02X %02X %02X %02X\n",
                    offsets[i], addr[0], addr[1], addr[2], addr[3], addr[4]);
        }
    }
    
    return patches;
}

// Pattern 3: Hook the X509_verify_cert function to always return 1
// X509_verify_cert returns 1 on success
int patch_x509_verify() {
    int patches = 0;
    
    // Search for X509_verify_cert string reference to find the function
    // The function likely starts with standard prologue and we can NOP it to return 1
    
    // Alternative: find the function by looking for its internal calls pattern
    // For now, just search for all "call xxx; test eax,eax; jne" patterns
    // which indicate success/failure branching after verification
    
    return patches;
}

DWORD WINAPI PatcherThread(LPVOID param) {
    log_msg("=== Dead Space 2 SSL Patcher v10 ===\n");
    log_msg("Waiting for DLL to be loaded and unpacked...\n");
    
    // Wait for the DLL to be loaded
    int retries = 0;
    while (!find_module(TARGET_DLL) && retries < 60) {
        Sleep(1000);
        retries++;
    }
    
    if (!g_module.base) {
        log_msg("ERROR: Could not find %s after %d seconds\n", TARGET_DLL, retries);
        return 1;
    }
    
    // Wait a bit more for unpacking
    log_msg("Found DLL, waiting 5 seconds for Themida unpacking...\n");
    Sleep(5000);
    
    // Re-acquire module info (base might change after unpacking)
    find_module(TARGET_DLL);
    
    log_msg("\nApplying patches...\n\n");
    
    int total = 0;
    
    // First apply the known verify_mode patches
    int p2 = patch_set_verify_calls();
    log_msg("Applied %d verify_mode patches\n\n", p2);
    total += p2;
    
    // Then try to patch callback result checks
    int p1 = patch_callback_result_checks();
    log_msg("Applied %d callback result patches\n\n", p1);
    total += p1;
    
    log_msg("=== Total patches applied: %d ===\n", total);
    
    if (logfile) {
        fclose(logfile);
        logfile = NULL;
    }
    
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        CreateThread(NULL, 0, PatcherThread, NULL, 0, NULL);
    }
    return TRUE;
}

// Standalone entry point
int main() {
    log_msg("Running as standalone executable...\n");
    PatcherThread(NULL);
    return 0;
}
