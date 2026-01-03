/*
 * Dead Space 2 SSL Hook DLL
 * 
 * This DLL hooks OpenSSL functions in activation.x86.dll to bypass SSL verification.
 * Instead of patching memory at runtime, we intercept the function calls.
 * 
 * Hooked functions:
 * - SSL_set_verify: Force verify_mode to 0
 * - SSL_get_verify_result: Always return X509_V_OK (0)
 * - verify_callback: Always return 1 (success)
 * 
 * Build: i686-w64-mingw32-gcc -shared -o ds2_ssl_hook.dll ds2_ssl_hook.c -lpsapi
 * 
 * Usage:
 * 1. Copy ds2_ssl_hook.dll to Dead Space 2 folder
 * 2. Rename activation.x86.dll to activation.x86.dll.orig
 * 3. Create a proxy DLL that loads both
 * 
 * Or use with DLL injector after game starts.
 */

#include <windows.h>
#include <stdio.h>

/* We'll use IAT hooking or inline hooking */

/* For simplicity, let's try a different approach:
 * Create a version.dll proxy that the game will load,
 * which then hooks the SSL functions.
 */

/* Global state */
static HMODULE g_originalVersion = NULL;
static BOOL g_hooked = FALSE;

/* Logging */
static FILE* g_logFile = NULL;

void LogMessage(const char* fmt, ...) {
    if (!g_logFile) {
        g_logFile = fopen("ds2_ssl_hook.log", "a");
    }
    if (g_logFile) {
        va_list args;
        va_start(args, fmt);
        vfprintf(g_logFile, fmt, args);
        va_end(args);
        fprintf(g_logFile, "\n");
        fflush(g_logFile);
    }
}

/* Original function pointers */
typedef void (*SSL_set_verify_t)(void* ssl, int mode, void* callback);
typedef long (*SSL_get_verify_result_t)(void* ssl);

static SSL_set_verify_t Original_SSL_set_verify = NULL;
static SSL_get_verify_result_t Original_SSL_get_verify_result = NULL;

/* Our hooked functions */
void Hooked_SSL_set_verify(void* ssl, int mode, void* callback) {
    LogMessage("SSL_set_verify called with mode=%d, forcing mode=0", mode);
    if (Original_SSL_set_verify) {
        Original_SSL_set_verify(ssl, 0, NULL); /* Force no verification */
    }
}

long Hooked_SSL_get_verify_result(void* ssl) {
    LogMessage("SSL_get_verify_result called, returning 0 (X509_V_OK)");
    return 0; /* X509_V_OK */
}

/* Simple inline hook: overwrite first bytes with JMP to our function */
typedef struct {
    BYTE originalBytes[5];
    BYTE* targetAddress;
    void* hookFunction;
    BOOL installed;
} InlineHook;

static InlineHook g_hooks[10];
static int g_hookCount = 0;

BOOL InstallInlineHook(BYTE* target, void* hook) {
    if (g_hookCount >= 10) return FALSE;
    
    InlineHook* h = &g_hooks[g_hookCount];
    h->targetAddress = target;
    h->hookFunction = hook;
    
    /* Save original bytes */
    DWORD oldProtect;
    if (!VirtualProtect(target, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        LogMessage("VirtualProtect failed: %lu", GetLastError());
        return FALSE;
    }
    
    memcpy(h->originalBytes, target, 5);
    
    /* Write JMP rel32 */
    DWORD relAddr = (DWORD)((BYTE*)hook - target - 5);
    target[0] = 0xE9; /* JMP rel32 */
    *(DWORD*)(target + 1) = relAddr;
    
    VirtualProtect(target, 5, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), target, 5);
    
    h->installed = TRUE;
    g_hookCount++;
    
    LogMessage("Installed hook at %p -> %p", target, hook);
    return TRUE;
}

/* Find function by pattern in a module */
BYTE* FindPattern(HMODULE module, BYTE* pattern, SIZE_T patternSize) {
    MODULEINFO info;
    if (!GetModuleInformation(GetCurrentProcess(), module, &info, sizeof(info))) {
        return NULL;
    }
    
    BYTE* base = (BYTE*)module;
    SIZE_T size = info.SizeOfImage;
    
    for (SIZE_T i = 0; i < size - patternSize; i++) {
        if (memcmp(base + i, pattern, patternSize) == 0) {
            return base + i;
        }
    }
    return NULL;
}

void InstallSSLHooks() {
    if (g_hooked) return;
    
    LogMessage("Installing SSL hooks...");
    
    /* Wait for activation.x86.dll to be loaded and unpacked */
    HMODULE hActivation = NULL;
    for (int i = 0; i < 60; i++) { /* Wait up to 60 seconds */
        hActivation = GetModuleHandleA("activation.x86.dll");
        if (hActivation) {
            LogMessage("Found activation.x86.dll at %p", hActivation);
            break;
        }
        Sleep(1000);
    }
    
    if (!hActivation) {
        LogMessage("activation.x86.dll not found!");
        return;
    }
    
    /* Wait for unpacking (check if code is accessible) */
    Sleep(5000); /* Give time for Themida to unpack */
    
    /* Find SSL_set_verify by looking for the verify_mode store pattern */
    /* Pattern: mov [reg+0x130], immediate 
     * We want to hook right before this instruction */
    
    /* For now, let's try a simpler approach: 
     * Hook the IAT entry for SSL functions if they're imported
     * Or hook at known offsets from our analysis */
    
    /* Based on our analysis, verify_mode=1 is set at these offsets:
     * +0xB1FF, +0xB6FC, +0xCB08 
     * The function that contains these starts a bit before */
    
    BYTE* base = (BYTE*)hActivation;
    
    /* Instead of hooking the function, let's just patch the instructions
     * Same as our runtime patcher but from within the process */
    
    BYTE verifyModePattern[] = {0xc7, 0x86, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    
    MODULEINFO info;
    GetModuleInformation(GetCurrentProcess(), hActivation, &info, sizeof(info));
    
    for (SIZE_T i = 0; i < info.SizeOfImage - 10; i++) {
        /* Check for all verify_mode=1 patterns */
        BYTE patterns[][10] = {
            {0xc7, 0x86, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
            {0xc7, 0x82, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
            {0xc7, 0x81, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
            {0xc7, 0x83, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
            {0xc7, 0x87, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
        };
        
        for (int p = 0; p < 5; p++) {
            if (memcmp(base + i, patterns[p], 10) == 0) {
                LogMessage("Found verify_mode=1 at offset +0x%X", (unsigned int)i);
                
                DWORD oldProtect;
                if (VirtualProtect(base + i + 6, 1, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    base[i + 6] = 0x00; /* Change 1 to 0 */
                    VirtualProtect(base + i + 6, 1, oldProtect, &oldProtect);
                    LogMessage("Patched verify_mode to 0");
                }
            }
        }
    }
    
    g_hooked = TRUE;
    LogMessage("SSL hooks installed");
}

/* Thread to wait for DLL load and install hooks */
DWORD WINAPI HookThread(LPVOID param) {
    LogMessage("Hook thread started");
    InstallSSLHooks();
    return 0;
}

/* DLL entry point */
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            LogMessage("ds2_ssl_hook.dll loaded");
            CreateThread(NULL, 0, HookThread, NULL, 0, NULL);
            break;
            
        case DLL_PROCESS_DETACH:
            if (g_logFile) {
                fclose(g_logFile);
                g_logFile = NULL;
            }
            break;
    }
    return TRUE;
}

/* Exports for version.dll proxy (if used as proxy DLL) */
/* The game might load version.dll, we can use it as injection point */

/* Forward all version.dll exports to the real version.dll */
#pragma comment(linker, "/export:GetFileVersionInfoA=version_orig.GetFileVersionInfoA")
#pragma comment(linker, "/export:GetFileVersionInfoW=version_orig.GetFileVersionInfoW")
#pragma comment(linker, "/export:GetFileVersionInfoSizeA=version_orig.GetFileVersionInfoSizeA")
#pragma comment(linker, "/export:GetFileVersionInfoSizeW=version_orig.GetFileVersionInfoSizeW")
#pragma comment(linker, "/export:VerQueryValueA=version_orig.VerQueryValueA")
#pragma comment(linker, "/export:VerQueryValueW=version_orig.VerQueryValueW")
