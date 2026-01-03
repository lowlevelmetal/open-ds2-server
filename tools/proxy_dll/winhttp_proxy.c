/*
 * Dead Space 2 SSL Bypass Proxy DLL
 * 
 * This DLL hooks into the game and intercepts SSL certificate verification
 * to allow connections to custom servers.
 * 
 * Build with: cl /LD /O2 winhttp_proxy.c /link ws2_32.lib
 * Or MinGW: i686-w64-mingw32-gcc -shared -o winhttp.dll winhttp_proxy.c -lws2_32
 * 
 * Place the resulting DLL in the Dead Space 2 game directory.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <stdio.h>

// Forward declarations for the real DLL functions
typedef BOOL (WINAPI *pWinHttpSetOption_t)(HINTERNET, DWORD, LPVOID, DWORD);
typedef HINTERNET (WINAPI *pWinHttpOpen_t)(LPCWSTR, DWORD, LPCWSTR, LPCWSTR, DWORD);
typedef HINTERNET (WINAPI *pWinHttpConnect_t)(HINTERNET, LPCWSTR, INTERNET_PORT, DWORD);
typedef HINTERNET (WINAPI *pWinHttpOpenRequest_t)(HINTERNET, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR*, DWORD);
typedef BOOL (WINAPI *pWinHttpSendRequest_t)(HINTERNET, LPCWSTR, DWORD, LPVOID, DWORD, DWORD, DWORD_PTR);

static HMODULE g_realDll = NULL;
static pWinHttpSetOption_t g_realSetOption = NULL;

// Security flags
#define SECURITY_FLAG_IGNORE_UNKNOWN_CA         0x00000100
#define SECURITY_FLAG_IGNORE_CERT_DATE_INVALID  0x00002000
#define SECURITY_FLAG_IGNORE_CERT_CN_INVALID    0x00001000
#define SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE   0x00000200

#define WINHTTP_OPTION_SECURITY_FLAGS 31

// Hook WinHttpSetOption to force ignore certificate errors
__declspec(dllexport) BOOL WINAPI WinHttpSetOption(
    HINTERNET hInternet,
    DWORD dwOption,
    LPVOID lpBuffer,
    DWORD dwBufferLength)
{
    if (!g_realDll) {
        char sysdir[MAX_PATH];
        GetSystemDirectoryA(sysdir, MAX_PATH);
        strcat(sysdir, "\\winhttp.dll");
        g_realDll = LoadLibraryA(sysdir);
        g_realSetOption = (pWinHttpSetOption_t)GetProcAddress(g_realDll, "WinHttpSetOption");
    }
    
    // If setting security options, add our ignore flags
    if (dwOption == WINHTTP_OPTION_SECURITY_FLAGS && lpBuffer && dwBufferLength >= sizeof(DWORD)) {
        DWORD flags = *(DWORD*)lpBuffer;
        flags |= SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                 SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                 SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                 SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE;
        *(DWORD*)lpBuffer = flags;
    }
    
    return g_realSetOption(hInternet, dwOption, lpBuffer, dwBufferLength);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(hinstDLL);
            // Could add logging here
            break;
        case DLL_PROCESS_DETACH:
            if (g_realDll) FreeLibrary(g_realDll);
            break;
    }
    return TRUE;
}
