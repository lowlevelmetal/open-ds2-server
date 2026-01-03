/*
 * Dead Space 2 SSL Bypass via dinput8.dll Proxy
 * 
 * This DLL proxies DirectInput8 and hooks SSL_CTX_set_verify in activation.x86.dll
 * to disable certificate verification.
 * 
 * Build with MinGW (32-bit):
 *   i686-w64-mingw32-gcc -shared -o dinput8.dll dinput8_proxy.c -ldinput8 -ldxguid
 * 
 * Or with MSVC:
 *   cl /LD /O2 dinput8_proxy.c dinput8.lib dxguid.lib
 * 
 * Place dinput8.dll in the Dead Space 2 game directory.
 */

#define WIN32_LEAN_AND_MEAN
#define CINTERFACE
#define COBJMACROS

#include <windows.h>
#include <dinput.h>
#include <stdio.h>

#pragma comment(lib, "dinput8.lib")
#pragma comment(lib, "dxguid.lib")

// ============================================================================
// DirectInput8 Proxy
// ============================================================================

typedef HRESULT (WINAPI *DirectInput8Create_t)(
    HINSTANCE hinst, DWORD dwVersion, REFIID riidltf, 
    LPVOID *ppvOut, LPUNKNOWN punkOuter);

static HMODULE g_realDInput8 = NULL;
static DirectInput8Create_t g_realDirectInput8Create = NULL;

// ============================================================================
// SSL Hooking
// ============================================================================

// OpenSSL SSL_CTX_set_verify signature
typedef void (*SSL_CTX_set_verify_t)(void* ctx, int mode, void* callback);

// Original function pointer
static SSL_CTX_set_verify_t g_originalSetVerify = NULL;

// Our hooked version - always sets mode to 0 (SSL_VERIFY_NONE)
void hooked_SSL_CTX_set_verify(void* ctx, int mode, void* callback)
{
    // Force SSL_VERIFY_NONE
    if (g_originalSetVerify) {
        g_originalSetVerify(ctx, 0, NULL);  // 0 = SSL_VERIFY_NONE, NULL callback
    }
}

// Simple IAT hook
BOOL HookIAT(HMODULE module, const char* dllName, const char* funcName, void* hookFunc, void** origFunc)
{
    // This is a simplified IAT hook - won't work for activation.x86.dll
    // because OpenSSL is statically linked (no IAT entry)
    return FALSE;
}

// Inline hook (x86) - patches the first bytes of a function
typedef struct {
    BYTE originalBytes[5];
    void* targetFunc;
} InlineHook;

BOOL CreateInlineHook(void* targetFunc, void* hookFunc, InlineHook* hook)
{
    if (!targetFunc || !hookFunc || !hook) return FALSE;
    
    hook->targetFunc = targetFunc;
    
    // Save original bytes
    DWORD oldProtect;
    if (!VirtualProtect(targetFunc, 5, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    memcpy(hook->originalBytes, targetFunc, 5);
    
    // Write JMP instruction
    BYTE* target = (BYTE*)targetFunc;
    target[0] = 0xE9;  // JMP rel32
    *(DWORD*)(target + 1) = (DWORD)((BYTE*)hookFunc - target - 5);
    
    VirtualProtect(targetFunc, 5, oldProtect, &oldProtect);
    FlushInstructionCache(GetCurrentProcess(), targetFunc, 5);
    
    return TRUE;
}

// Find SSL_CTX_set_verify in activation.x86.dll by pattern matching
void* FindSSLSetVerify(HMODULE activationDll)
{
    if (!activationDll) return NULL;
    
    // Get module info
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), activationDll, &modInfo, sizeof(modInfo))) {
        return NULL;
    }
    
    BYTE* base = (BYTE*)modInfo.lpBaseOfDll;
    DWORD size = modInfo.SizeOfImage;
    
    // Pattern for SSL_CTX_set_verify function prologue
    // This varies by OpenSSL version, but common patterns exist
    
    // For OpenSSL 1.0.0, SSL_CTX_set_verify typically:
    // - Takes ctx in first param (stack or ECX)
    // - Sets ctx->verify_mode = mode
    // - Sets ctx->verify_callback = callback
    
    // We'll search for the string "SSL_CTX_set_verify" which is used in error messages
    // Then find cross-references to it
    
    // For now, return NULL - we need runtime analysis
    return NULL;
}

// ============================================================================
// Memory Scanning
// ============================================================================

// Scan for byte pattern
BYTE* ScanPattern(BYTE* start, SIZE_T size, const BYTE* pattern, const char* mask, SIZE_T patternLen)
{
    for (SIZE_T i = 0; i < size - patternLen; i++) {
        BOOL found = TRUE;
        for (SIZE_T j = 0; j < patternLen; j++) {
            if (mask[j] == 'x' && start[i + j] != pattern[j]) {
                found = FALSE;
                break;
            }
        }
        if (found) {
            return start + i;
        }
    }
    return NULL;
}

// Hook SSL verification by patching the verify mode push instructions
BOOL PatchSSLVerifyMode(HMODULE activationDll)
{
    if (!activationDll) return FALSE;
    
    MODULEINFO modInfo;
    if (!GetModuleInformation(GetCurrentProcess(), activationDll, &modInfo, sizeof(modInfo))) {
        return FALSE;
    }
    
    BYTE* base = (BYTE*)modInfo.lpBaseOfDll;
    SIZE_T size = modInfo.SizeOfImage;
    
    // Make the entire module writable temporarily
    DWORD oldProtect;
    
    int patchCount = 0;
    
    // Search for: 6A 01 (push 1) or 6A 02 (push 2) or 6A 03 (push 3)
    // followed within ~20 bytes by E8 (call)
    // These are the SSL_CTX_set_verify calls with SSL_VERIFY_PEER etc.
    
    // Known offsets for Steam version (MD5: fde0585b30ddb8deb1f60b5af9a4a001)
    // These would need to be discovered through analysis
    
    // For now, we'll do runtime scanning
    for (SIZE_T i = 0; i < size - 20; i++) {
        // Look for push 1/2/3
        if (base[i] == 0x6A && (base[i+1] == 0x01 || base[i+1] == 0x02 || base[i+1] == 0x03)) {
            // Check if there's a CALL instruction within next 15 bytes
            BOOL hasCall = FALSE;
            for (int j = 2; j < 15; j++) {
                if (base[i + j] == 0xE8) {
                    hasCall = TRUE;
                    break;
                }
            }
            
            if (hasCall) {
                // This might be an SSL verify call - but we need to be careful
                // Only patch if we're confident this is in the SSL code section
                
                // Check if nearby we have other SSL-related patterns
                // This is a heuristic to avoid false positives
            }
        }
    }
    
    return patchCount > 0;
}

// ============================================================================
// Initialization
// ============================================================================

void InitSSLBypass()
{
    // Wait a bit for activation.x86.dll to be loaded and unpacked
    Sleep(1000);
    
    HMODULE activationDll = GetModuleHandleA("activation.x86.dll");
    if (!activationDll) {
        // Try loading it
        activationDll = LoadLibraryA("activation.x86.dll");
    }
    
    if (activationDll) {
        // The DLL is protected/packed, so we need runtime patching
        // after the unpacking stub has run
        
        // Option 1: Hook by export name (if exported)
        void* setVerify = GetProcAddress(activationDll, "SSL_CTX_set_verify");
        if (setVerify) {
            // Direct hook
            // CreateInlineHook(setVerify, hooked_SSL_CTX_set_verify, &g_hookInfo);
        }
        
        // Option 2: Pattern scan after unpacking
        // This requires knowing when unpacking is complete
    }
}

// ============================================================================
// DLL Entry Point
// ============================================================================

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            
            // Load the real dinput8.dll from system directory
            {
                char sysdir[MAX_PATH];
                GetSystemDirectoryA(sysdir, MAX_PATH);
                strcat(sysdir, "\\dinput8.dll");
                g_realDInput8 = LoadLibraryA(sysdir);
                if (g_realDInput8) {
                    g_realDirectInput8Create = (DirectInput8Create_t)
                        GetProcAddress(g_realDInput8, "DirectInput8Create");
                }
            }
            
            // Initialize SSL bypass in a separate thread
            // (to not block DLL loading)
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)InitSSLBypass, NULL, 0, NULL);
            break;
            
        case DLL_PROCESS_DETACH:
            if (g_realDInput8) {
                FreeLibrary(g_realDInput8);
            }
            break;
    }
    return TRUE;
}

// ============================================================================
// Exported Functions (proxy to real dinput8.dll)
// ============================================================================

__declspec(dllexport) HRESULT WINAPI DirectInput8Create(
    HINSTANCE hinst, 
    DWORD dwVersion, 
    REFIID riidltf, 
    LPVOID *ppvOut, 
    LPUNKNOWN punkOuter)
{
    if (g_realDirectInput8Create) {
        return g_realDirectInput8Create(hinst, dwVersion, riidltf, ppvOut, punkOuter);
    }
    return E_FAIL;
}
