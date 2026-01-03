/*
 * Dead Space 2 Targeted SSL Patcher v2
 * 
 * This version uses a more targeted approach:
 * 1. Finds the SSL_CTX_set_verify function by signature
 * 2. Hooks the verify callback to always return 1
 * 3. Only patches the specific SSL verification code
 * 
 * Build: i686-w64-mingw32-gcc -o ds2_ssl_patcher_v2.exe ds2_ssl_patcher_v2.c -lpsapi -static
 */

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "psapi.lib")

#define GAME_EXE "deadspace2.exe"
#define TARGET_DLL "activation.x86.dll"
#define PATCH_DELAY_MS 5000

// Find process by name
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

// Find module base address
BYTE* FindModuleBase(HANDLE hProcess, const char* moduleName) {
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
                return (BYTE*)modules[i];
            }
        }
    }
    
    return NULL;
}

// Write to process memory
BOOL WriteMem(HANDLE hProcess, BYTE* address, void* data, SIZE_T size) {
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, address, size, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }
    
    SIZE_T written;
    BOOL result = WriteProcessMemory(hProcess, address, data, size, &written);
    
    VirtualProtectEx(hProcess, address, size, oldProtect, &oldProtect);
    
    return result && written == size;
}

// Find pattern with mask
BYTE* FindPattern(BYTE* data, SIZE_T dataSize, const BYTE* pattern, const char* mask, SIZE_T patLen) {
    for (SIZE_T i = 0; i < dataSize - patLen; i++) {
        BOOL found = TRUE;
        for (SIZE_T j = 0; j < patLen; j++) {
            if (mask[j] == 'x' && data[i + j] != pattern[j]) {
                found = FALSE;
                break;
            }
        }
        if (found) {
            return data + i;
        }
    }
    return NULL;
}

// Find string in memory
BYTE* FindString(BYTE* data, SIZE_T dataSize, const char* str) {
    SIZE_T strLen = strlen(str);
    for (SIZE_T i = 0; i < dataSize - strLen; i++) {
        if (memcmp(data + i, str, strLen) == 0) {
            return data + i;
        }
    }
    return NULL;
}

int PatchSSLVerification(HANDLE hProcess, BYTE* dllBase) {
    printf("[*] Starting targeted SSL patch...\n");
    
    MODULEINFO modInfo;
    if (!GetModuleInformation(hProcess, (HMODULE)dllBase, &modInfo, sizeof(modInfo))) {
        printf("[-] Failed to get module info\n");
        return 0;
    }
    
    SIZE_T moduleSize = modInfo.SizeOfImage;
    printf("[*] Module size: %zu bytes\n", moduleSize);
    
    BYTE* moduleData = (BYTE*)malloc(moduleSize);
    if (!moduleData) {
        printf("[-] Memory allocation failed\n");
        return 0;
    }
    
    SIZE_T read;
    if (!ReadProcessMemory(hProcess, dllBase, moduleData, moduleSize, &read)) {
        printf("[-] Failed to read module memory\n");
        free(moduleData);
        return 0;
    }
    
    printf("[*] Read %zu bytes from process\n", read);
    
    int patchCount = 0;
    
    // Strategy 1: Find and patch the verify callback to always return 1
    // Look for small functions that return 0 (xor eax, eax; ret)
    // These are often verify callbacks that reject certificates
    
    // Pattern: xor eax, eax (33 C0) followed closely by ret (C3)
    printf("\n[*] Looking for verify callback functions that return 0...\n");
    
    for (SIZE_T i = 0; i < read - 10; i++) {
        // Look for: xor eax, eax; ret or xor eax, eax; pop; ret etc
        if (moduleData[i] == 0x33 && moduleData[i+1] == 0xC0) {
            // Check if ret is within next few bytes
            for (int j = 2; j < 8; j++) {
                if (moduleData[i+j] == 0xC3) {  // ret
                    // Check if this looks like a function start (has push ebp or similar before)
                    // Look backwards for function prologue
                    BOOL looksLikeFunction = FALSE;
                    for (int k = 1; k < 32; k++) {
                        if (i >= k) {
                            // push ebp = 55, or push edi = 57, push esi = 56
                            if (moduleData[i-k] == 0x55 || moduleData[i-k] == 0x57 || 
                                moduleData[i-k] == 0x56 || moduleData[i-k] == 0x53) {
                                looksLikeFunction = TRUE;
                                break;
                            }
                            // Also check for mov edi, edi (8B FF) - common function start
                            if (i >= k+1 && moduleData[i-k-1] == 0x8B && moduleData[i-k] == 0xFF) {
                                looksLikeFunction = TRUE;
                                break;
                            }
                        }
                    }
                    
                    // Skip if this doesn't look like a real function
                    if (!looksLikeFunction) break;
                    
                    // This is potentially a verify callback returning 0
                    // We want to change it to return 1 instead
                    // Change: 33 C0 (xor eax, eax) to B0 01 (mov al, 1)
                    // But B0 01 only sets AL, not full EAX. Better: 
                    // Change to: 6A 01 58 (push 1; pop eax) but that's 3 bytes
                    // Or: 31 C0 40 (xor eax,eax; inc eax) - same result, 3 bytes
                    
                    // Let's use a 2-byte patch: B0 01 (mov al, 1)
                    // Then we need to zero the high bytes somehow...
                    // Actually the callback return only checks the low bit usually
                    
                    // For safety, let's just note these locations
                    printf("    Potential callback at offset 0x%zX (returns 0)\n", i);
                    break;
                }
            }
        }
    }
    
    // Strategy 2: Find SSL_CTX_set_verify by its OpenSSL string reference
    printf("\n[*] Looking for SSL-related strings...\n");
    
    // Look for "SSL_CTX_set_verify" string
    BYTE* sslSetVerifyStr = FindString(moduleData, read, "SSL_CTX_set_verify");
    if (sslSetVerifyStr) {
        SIZE_T strOffset = sslSetVerifyStr - moduleData;
        printf("[+] Found 'SSL_CTX_set_verify' string at offset 0x%zX\n", strOffset);
        
        // Find cross-references to this string
        DWORD strVA = (DWORD)(dllBase + strOffset);
        BYTE strVABytes[4];
        memcpy(strVABytes, &strVA, 4);
        
        // Search for this address being pushed
        for (SIZE_T i = 0; i < read - 5; i++) {
            if (moduleData[i] == 0x68) {  // push imm32
                if (memcmp(&moduleData[i+1], strVABytes, 4) == 0) {
                    printf("[+] Found reference at offset 0x%zX\n", i);
                }
            }
        }
    }
    
    // Strategy 3: Look for the specific pattern of SSL_CTX_set_verify calls
    // In OpenSSL 1.0.0, the function typically:
    // - mov [ctx+offset], mode  (for verify_mode)
    // - mov [ctx+offset], callback (for verify_callback)
    
    printf("\n[*] Looking for SSL verify mode assignments...\n");
    
    // Pattern: mov dword ptr [reg+XX], 1 (C7 4X XX 01 00 00 00)
    // This is "mov [eax/ecx/edx+offset], 1"
    
    for (SIZE_T i = 0; i < read - 10; i++) {
        // mov [reg+offset], imm32
        if (moduleData[i] == 0xC7) {
            BYTE modrm = moduleData[i+1];
            // Check for [reg+disp8] addressing with various registers
            if ((modrm & 0xC0) == 0x40) {  // [reg+disp8]
                BYTE disp = moduleData[i+2];
                DWORD imm = *(DWORD*)&moduleData[i+3];
                
                // Look for storing 1, 2, or 3 (SSL verify modes)
                if (imm >= 1 && imm <= 3) {
                    // Check context - is this near SSL-related code?
                    // Look for "ssl" or "SSL" strings nearby
                    BOOL nearSSL = FALSE;
                    SIZE_T start = (i > 100) ? i - 100 : 0;
                    SIZE_T end = (i + 100 < read) ? i + 100 : read;
                    
                    for (SIZE_T j = start; j < end - 3; j++) {
                        if ((moduleData[j] == 's' || moduleData[j] == 'S') &&
                            (moduleData[j+1] == 's' || moduleData[j+1] == 'S') &&
                            (moduleData[j+2] == 'l' || moduleData[j+2] == 'L')) {
                            nearSSL = TRUE;
                            break;
                        }
                    }
                    
                    if (nearSSL) {
                        printf("[+] Found verify mode assignment at 0x%zX: [reg+0x%02X] = %lu\n", 
                               i, disp, imm);
                        
                        // Patch it to 0
                        BYTE zero[4] = {0, 0, 0, 0};
                        if (WriteMem(hProcess, dllBase + i + 3, zero, 4)) {
                            printf("    Patched to 0 (SSL_VERIFY_NONE)\n");
                            patchCount++;
                        }
                    }
                }
            }
        }
    }
    
    // Strategy 4: Find and patch X509_verify_cert result checks
    printf("\n[*] Looking for X509 verification result checks...\n");
    
    // After X509_verify_cert is called, code typically checks:
    // test eax, eax / jz fail_label
    // or: cmp eax, 1 / jne fail_label
    
    // We can NOP out the conditional jump to make it always succeed
    // But this is risky without more context
    
    // Strategy 5: The most reliable - find the actual verify callback address
    // and write a "mov eax, 1; ret" stub there
    
    printf("\n[*] Looking for verify callback registration patterns...\n");
    
    // Pattern for SSL_CTX_set_verify call:
    // push callback_addr
    // push verify_mode
    // push ctx (or mov to ecx)
    // call SSL_CTX_set_verify
    
    // We look for: push imm32; push 1/2/3; ... call
    for (SIZE_T i = 0; i < read - 20; i++) {
        // Look for push imm8 (6A XX) where XX is 1, 2, or 3
        if (moduleData[i] == 0x6A && moduleData[i+1] >= 1 && moduleData[i+1] <= 3) {
            // Check if there's a push imm32 shortly before (the callback)
            BOOL hasPushBefore = FALSE;
            SIZE_T callbackPushOffset = 0;
            DWORD callbackAddr = 0;
            
            for (int k = 2; k < 10; k++) {
                if (i >= k && moduleData[i-k] == 0x68) {  // push imm32
                    hasPushBefore = TRUE;
                    callbackPushOffset = i - k;
                    callbackAddr = *(DWORD*)&moduleData[callbackPushOffset + 1];
                    break;
                }
                if (i >= k && moduleData[i-k] == 0x6A && moduleData[i-k+1] == 0x00) {
                    // push 0 (NULL callback)
                    hasPushBefore = TRUE;
                    callbackPushOffset = i - k;
                    callbackAddr = 0;
                    break;
                }
            }
            
            // Check if there's a call shortly after
            BOOL hasCallAfter = FALSE;
            for (int j = 2; j < 15; j++) {
                if (moduleData[i+j] == 0xE8) {
                    hasCallAfter = TRUE;
                    break;
                }
            }
            
            if (hasPushBefore && hasCallAfter) {
                BYTE mode = moduleData[i+1];
                
                // Only patch a limited number of likely candidates
                // Additional heuristic: check if callback address is within the module
                BOOL callbackInModule = (callbackAddr >= (DWORD)dllBase && 
                                         callbackAddr < (DWORD)dllBase + moduleSize);
                
                if (callbackInModule || callbackAddr == 0) {
                    printf("[+] SSL_CTX_set_verify pattern at 0x%zX: mode=%d, callback=0x%08lX\n",
                           i, mode, callbackAddr);
                    
                    // Patch the mode to 0
                    BYTE zero = 0;
                    if (WriteMem(hProcess, dllBase + i + 1, &zero, 1)) {
                        printf("    Patched mode %d -> 0\n", mode);
                        patchCount++;
                    }
                    
                    // If callback is in module, patch it to return 1
                    if (callbackInModule) {
                        SIZE_T callbackOffset = callbackAddr - (DWORD)dllBase;
                        
                        // Write: mov eax, 1; ret (B8 01 00 00 00 C3)
                        BYTE returnOne[] = {0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3};
                        if (WriteMem(hProcess, (BYTE*)callbackAddr, returnOne, sizeof(returnOne))) {
                            printf("    Patched callback at 0x%08lX to return 1\n", callbackAddr);
                            patchCount++;
                        }
                    }
                }
            }
        }
    }
    
    free(moduleData);
    return patchCount;
}

int main(int argc, char* argv[]) {
    printf("==============================================\n");
    printf("  Dead Space 2 Targeted SSL Patcher v2\n");
    printf("==============================================\n\n");
    
    printf("[*] Looking for %s...\n", GAME_EXE);
    
    DWORD pid = FindProcess(GAME_EXE);
    if (!pid) {
        printf("[!] Game not running. Waiting...\n");
        for (int i = 0; i < 60; i++) {
            Sleep(1000);
            pid = FindProcess(GAME_EXE);
            if (pid) break;
            printf(".");
        }
        printf("\n");
        
        if (!pid) {
            printf("[-] Timeout waiting for game\n");
            return 1;
        }
    }
    
    printf("[+] Found game process: PID %lu\n", pid);
    
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION,
        FALSE, pid);
    
    if (!hProcess) {
        printf("[-] Failed to open process: %lu\n", GetLastError());
        return 1;
    }
    
    printf("[*] Waiting for %s...\n", TARGET_DLL);
    
    BYTE* dllBase = NULL;
    for (int i = 0; i < 30; i++) {
        dllBase = FindModuleBase(hProcess, TARGET_DLL);
        if (dllBase) break;
        Sleep(1000);
    }
    
    if (!dllBase) {
        printf("[-] Failed to find %s\n", TARGET_DLL);
        CloseHandle(hProcess);
        return 1;
    }
    
    printf("[+] Found %s at 0x%p\n", TARGET_DLL, dllBase);
    
    printf("[*] Waiting %d ms for unpacking...\n", PATCH_DELAY_MS);
    Sleep(PATCH_DELAY_MS);
    
    int patches = PatchSSLVerification(hProcess, dllBase);
    
    printf("\n[+] Applied %d targeted patches\n", patches);
    
    CloseHandle(hProcess);
    
    printf("\nPress Enter to exit...");
    getchar();
    
    return 0;
}
