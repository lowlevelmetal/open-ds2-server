/*
 * Dead Space 2 SSL Patcher v4 - Targeted Certificate Bypass
 * 
 * Based on analysis of the dumped activation.x86.dll:
 * - The DLL uses statically linked OpenSSL 1.0.0b
 * - X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY (error 20) is set at multiple locations
 * - The SSL handshake fails because the game can't verify our server certificate
 * 
 * This version specifically targets:
 * 1. The SSL verify_mode field in SSL/SSL_CTX structures
 * 2. X509 verification error code assignments 
 * 3. The ssl_verify_cert_chain result checks
 * 
 * Build: i686-w64-mingw32-gcc -o ds2_ssl_patcher_v4.exe ds2_ssl_patcher_v4.c -lpsapi -static -O2
 */

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

#define GAME_EXE "deadspace2.exe"
#define TARGET_DLL "activation.x86.dll"

/* Known offsets from analysis of dumped DLL */
/* .text section: VA=0x1000, RawPtr=0x400 */
/* Image base when loaded: 0x795e0000 (but can vary) */

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

BOOL ReadMem(HANDLE hProcess, BYTE* address, void* buffer, SIZE_T size) {
    SIZE_T read;
    return ReadProcessMemory(hProcess, address, buffer, size, &read) && read == size;
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

/* Find pattern in memory with mask */
SIZE_T FindPattern(BYTE* data, SIZE_T dataSize, const BYTE* pattern, const char* mask, SIZE_T patLen) {
    for (SIZE_T i = 0; i < dataSize - patLen; i++) {
        BOOL found = TRUE;
        for (SIZE_T j = 0; j < patLen; j++) {
            if (mask[j] == 'x' && data[i + j] != pattern[j]) {
                found = FALSE;
                break;
            }
        }
        if (found) return i;
    }
    return (SIZE_T)-1;
}

/* Find all occurrences of a pattern */
int FindAllPatterns(BYTE* data, SIZE_T dataSize, const BYTE* pattern, SIZE_T patLen,
                    SIZE_T* results, int maxResults) {
    int count = 0;
    for (SIZE_T i = 0; i < dataSize - patLen && count < maxResults; i++) {
        if (memcmp(data + i, pattern, patLen) == 0) {
            results[count++] = i;
        }
    }
    return count;
}

int PatchSSLVerification(HANDLE hProcess, BYTE* dllBase, DWORD moduleSize) {
    printf("[*] Reading module memory (%lu bytes)...\n", moduleSize);
    
    BYTE* moduleData = (BYTE*)malloc(moduleSize);
    if (!moduleData) {
        printf("[-] Memory allocation failed\n");
        return 0;
    }
    
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, dllBase, moduleData, moduleSize, &bytesRead)) {
        printf("[-] Failed to read module memory\n");
        free(moduleData);
        return 0;
    }
    printf("[+] Read %zu bytes\n", bytesRead);
    
    int totalPatches = 0;
    SIZE_T offsets[256];
    int count;
    
    /* ============================================================
     * PATCH 1: Patch X509 error code assignments
     * 
     * When certificate verification fails, OpenSSL sets error codes.
     * X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY = 20 (0x14)
     * We change these to X509_V_OK = 0
     * 
     * Pattern: C7 XX XX 14 00 00 00 (mov [reg+XX], 0x14)
     * Change to: C7 XX XX 00 00 00 00 (mov [reg+XX], 0x00)
     * ============================================================ */
    printf("\n[*] Patch 1: X509 error code assignments (error 20 -> 0)...\n");
    
    int errorPatches = 0;
    for (SIZE_T i = 0; i < bytesRead - 10; i++) {
        /* mov dword ptr [reg+XX], 0x14 (error 20) */
        /* C7 40 XX 14 00 00 00 - [eax+byte] */
        /* C7 41 XX 14 00 00 00 - [ecx+byte] */
        /* C7 80 XX XX XX XX 14 00 00 00 - [eax+dword] */
        
        if (moduleData[i] == 0xC7) {
            BOOL isError20 = FALSE;
            SIZE_T valueOffset = 0;
            
            /* [eax+byte], [ecx+byte], etc. */
            if ((moduleData[i+1] & 0xF8) == 0x40) {  /* 40-47 */
                if (moduleData[i+3] == 0x14 && moduleData[i+4] == 0x00 &&
                    moduleData[i+5] == 0x00 && moduleData[i+6] == 0x00) {
                    isError20 = TRUE;
                    valueOffset = i + 3;
                }
            }
            /* [eax+dword], [ecx+dword], etc. */
            else if ((moduleData[i+1] & 0xF8) == 0x80) {  /* 80-87 */
                if (moduleData[i+6] == 0x14 && moduleData[i+7] == 0x00 &&
                    moduleData[i+8] == 0x00 && moduleData[i+9] == 0x00) {
                    isError20 = TRUE;
                    valueOffset = i + 6;
                }
            }
            /* [ebp-XX] */
            else if (moduleData[i+1] == 0x45) {
                if (moduleData[i+3] == 0x14 && moduleData[i+4] == 0x00 &&
                    moduleData[i+5] == 0x00 && moduleData[i+6] == 0x00) {
                    isError20 = TRUE;
                    valueOffset = i + 3;
                }
            }
            
            if (isError20 && errorPatches < 50) {
                /* Change 0x14 to 0x00 (X509_V_OK) */
                BYTE zero = 0x00;
                if (WriteMem(hProcess, dllBase + valueOffset, &zero, 1)) {
                    errorPatches++;
                }
            }
        }
    }
    printf("[+] Patched %d error code assignments\n", errorPatches);
    totalPatches += errorPatches;
    
    /* ============================================================
     * PATCH 2: Patch error 21 (UNABLE_TO_VERIFY_LEAF_SIGNATURE)
     * Found at offset 0x4e33: C7 45 E0 15 00 00 00
     * ============================================================ */
    printf("\n[*] Patch 2: Error 21 assignment...\n");
    
    /* mov dword ptr [ebp-0x20], 0x15 = C7 45 E0 15 00 00 00 */
    const BYTE err21Pattern[] = {0xC7, 0x45, 0xE0, 0x15, 0x00, 0x00, 0x00};
    SIZE_T err21Offset = FindPattern(moduleData, bytesRead, err21Pattern, "xxxxxxx", 7);
    if (err21Offset != (SIZE_T)-1) {
        BYTE zero = 0x00;
        if (WriteMem(hProcess, dllBase + err21Offset + 3, &zero, 1)) {
            printf("[+] Patched error 21 at offset 0x%zX\n", err21Offset);
            totalPatches++;
        }
    }
    
    /* ============================================================
     * PATCH 3: Patch SSL_CTX->verify_mode assignments
     * 
     * From analysis: mov [eax+0x130], 0 and mov [eax+0x190], callback
     * We ensure verify_mode stays 0 (SSL_VERIFY_NONE)
     * ============================================================ */
    printf("\n[*] Patch 3: SSL_CTX verify_mode...\n");
    
    int verifyModePatches = 0;
    for (SIZE_T i = 0; i < bytesRead - 10; i++) {
        /* Look for: mov [edi+0x130], reg - 89 XX 30 01 00 00 */
        if (moduleData[i] == 0x89 && 
            moduleData[i+2] == 0x30 && moduleData[i+3] == 0x01 &&
            moduleData[i+4] == 0x00 && moduleData[i+5] == 0x00) {
            
            /* Change to: mov [edi+0x130], 0 - C7 87 30 01 00 00 00 00 00 00 */
            /* But that's 10 bytes vs 6, so instead NOP and set eax=0 before */
            /* Or just ensure the register being stored is 0 */
            
            /* Simpler: insert xor eax,eax before if there's room */
            /* For now, just log these locations */
            printf("    Found verify_mode store at offset 0x%zX\n", i);
            verifyModePatches++;
        }
    }
    printf("[+] Found %d verify_mode stores\n", verifyModePatches);
    
    /* ============================================================
     * PATCH 4: Patch ssl_verify_cert_chain result checks
     * 
     * After ssl_verify_cert_chain returns, code checks:
     * test eax, eax
     * jz error_handler  (if result is 0, fail)
     * 
     * We NOP out the conditional jump to always continue
     * ============================================================ */
    printf("\n[*] Patch 4: ssl_verify_cert_chain result checks...\n");
    
    int chainPatches = 0;
    for (SIZE_T i = 5; i < bytesRead - 10; i++) {
        /* Pattern: E8 XX XX XX XX 85 C0 74 XX (call; test eax,eax; jz short) */
        if (moduleData[i-5] == 0xE8 &&              /* call */
            moduleData[i] == 0x85 && moduleData[i+1] == 0xC0 &&  /* test eax, eax */
            moduleData[i+2] == 0x74) {               /* jz short */
            
            BYTE jmpDist = moduleData[i+3];
            
            /* Only patch significant jumps (likely error handlers) */
            if (jmpDist > 5 && chainPatches < 30) {
                /* NOP out the jz (2 bytes: 74 XX -> 90 90) */
                BYTE nops[2] = {0x90, 0x90};
                if (WriteMem(hProcess, dllBase + i + 2, nops, 2)) {
                    chainPatches++;
                }
            }
        }
        
        /* Pattern: E8 XX XX XX XX 85 C0 0F 84 XX XX XX XX (call; test eax,eax; jz near) */
        if (moduleData[i-5] == 0xE8 &&
            moduleData[i] == 0x85 && moduleData[i+1] == 0xC0 &&
            moduleData[i+2] == 0x0F && moduleData[i+3] == 0x84) {
            
            if (chainPatches < 30) {
                /* NOP out the near jz (6 bytes) */
                BYTE nops[6] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
                if (WriteMem(hProcess, dllBase + i + 2, nops, 6)) {
                    chainPatches++;
                }
            }
        }
    }
    printf("[+] Patched %d chain result checks\n", chainPatches);
    totalPatches += chainPatches;
    
    /* ============================================================
     * PATCH 5: Patch X509_verify_cert return value checks
     * 
     * X509_verify_cert returns 1 on success, 0 or negative on failure
     * Pattern: call X509_verify_cert; cmp eax, 1; jne error
     * Or: call X509_verify_cert; dec eax; jnz error
     * ============================================================ */
    printf("\n[*] Patch 5: X509_verify_cert result checks...\n");
    
    int x509Patches = 0;
    for (SIZE_T i = 5; i < bytesRead - 12; i++) {
        /* call; cmp eax, 1; jne */
        if (moduleData[i-5] == 0xE8 &&
            moduleData[i] == 0x83 && moduleData[i+1] == 0xF8 && moduleData[i+2] == 0x01 &&
            moduleData[i+3] == 0x75) {
            
            if (x509Patches < 20) {
                /* NOP out jne (2 bytes) */
                BYTE nops[2] = {0x90, 0x90};
                if (WriteMem(hProcess, dllBase + i + 3, nops, 2)) {
                    x509Patches++;
                }
            }
        }
        
        /* call; dec eax; jnz */
        if (moduleData[i-5] == 0xE8 &&
            moduleData[i] == 0x48 &&  /* dec eax */
            moduleData[i+1] == 0x75) {  /* jnz */
            
            if (x509Patches < 20) {
                /* Change jnz to jmp (always take success path): 75 XX -> EB XX */
                /* Or NOP it out: 75 XX -> 90 90 */
                BYTE nops[2] = {0x90, 0x90};
                if (WriteMem(hProcess, dllBase + i + 1, nops, 2)) {
                    x509Patches++;
                }
            }
        }
    }
    printf("[+] Patched %d X509_verify_cert checks\n", x509Patches);
    totalPatches += x509Patches;
    
    /* ============================================================
     * PATCH 6: Force ssl_verify_cert_chain to return 1
     * 
     * Find the function and patch its return to always succeed
     * Look for: xor eax, eax (failure return) and change to mov eax, 1
     * ============================================================ */
    printf("\n[*] Patch 6: Force successful verification returns...\n");
    
    int returnPatches = 0;
    for (SIZE_T i = 3; i < bytesRead - 10; i++) {
        /* Pattern: xor eax, eax; pop XXX; ret or xor eax, eax; ret */
        /* 33 C0 5X C3 or 31 C0 5X C3 or 33 C0 C3 */
        
        BOOL isXorEax = (moduleData[i] == 0x33 && moduleData[i+1] == 0xC0) ||
                        (moduleData[i] == 0x31 && moduleData[i+1] == 0xC0);
        
        if (isXorEax) {
            /* Check what follows */
            int retOffset = -1;
            
            if (moduleData[i+2] == 0xC3) {
                retOffset = i + 2;
            }
            else if (moduleData[i+2] >= 0x58 && moduleData[i+2] <= 0x5F &&  /* pop reg */
                     moduleData[i+3] == 0xC3) {
                retOffset = i + 3;
            }
            else if (moduleData[i+2] == 0x5D && moduleData[i+3] == 0xC3) {  /* pop ebp; ret */
                retOffset = i + 3;
            }
            
            if (retOffset > 0) {
                /* Check if this looks like it's in the .text section (code) */
                /* and if there's a function prologue somewhat before */
                BOOL inCodeSection = (i >= 0x400 && i < 0x70400);  /* .text section range */
                
                if (inCodeSection && returnPatches < 30) {
                    /* Change xor eax,eax to xor eax,eax; inc eax */
                    /* 33 C0 -> 33 C0 40 (we overwrite the next byte) */
                    /* But we need to be careful not to break following code */
                    
                    /* Safer: just change 33 C0 to B0 01 (mov al, 1) - assumes high bytes are 0 */
                    /* This is 2 bytes for 2 bytes, safe replacement */
                    BYTE movAl1[2] = {0xB0, 0x01};
                    if (WriteMem(hProcess, dllBase + i, movAl1, 2)) {
                        returnPatches++;
                    }
                }
            }
        }
    }
    printf("[+] Patched %d return-0 to return-1\n", returnPatches);
    totalPatches += returnPatches;
    
    /* ============================================================
     * PATCH 7: Specific patterns from analysis
     * 
     * VA 0x795ebc94: mov [edi+0x130], eax - sets verify_mode
     * We want to ensure eax=0 before this
     * ============================================================ */
    printf("\n[*] Patch 7: Specific verify_mode stores...\n");
    
    /* Pattern: 89 87 30 01 00 00 (mov [edi+0x130], eax) */
    const BYTE verifyModePattern[] = {0x89, 0x87, 0x30, 0x01, 0x00, 0x00};
    count = FindAllPatterns(moduleData, bytesRead, verifyModePattern, 6, offsets, 20);
    
    int specificPatches = 0;
    for (int i = 0; i < count; i++) {
        /* Insert xor eax, eax before this instruction */
        /* We need space - check if there's NOPs or something patchable before */
        if (offsets[i] >= 2) {
            /* Check if we can insert xor eax,eax (31 C0) before */
            /* For now, just log it */
            printf("    Found mov [edi+0x130], eax at offset 0x%zX\n", offsets[i]);
        }
    }
    
    free(moduleData);
    
    printf("\n[*] Total patches applied: %d\n", totalPatches);
    return totalPatches;
}

int main(int argc, char* argv[]) {
    printf("===========================================\n");
    printf(" Dead Space 2 SSL Patcher v4\n");
    printf(" Targeted Certificate Verification Bypass\n");
    printf("===========================================\n\n");
    
    /* Wait for game to start */
    printf("[*] Waiting for %s...\n", GAME_EXE);
    
    DWORD pid = 0;
    int waitCount = 0;
    while (pid == 0) {
        pid = FindProcess(GAME_EXE);
        if (pid == 0) {
            Sleep(1000);
            waitCount++;
            if (waitCount % 10 == 0) {
                printf("[*] Still waiting... (%d seconds)\n", waitCount);
            }
        }
    }
    
    printf("[+] Found process: PID %lu\n", pid);
    
    /* Wait for DLL to be loaded */
    printf("[*] Waiting for %s to load...\n", TARGET_DLL);
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process (error %lu)\n", GetLastError());
        printf("    Try running as Administrator\n");
        return 1;
    }
    
    BYTE* dllBase = NULL;
    DWORD moduleSize = 0;
    int dllWait = 0;
    
    while (dllBase == NULL && dllWait < 120) {
        dllBase = FindModuleBase(hProcess, TARGET_DLL, &moduleSize);
        if (dllBase == NULL) {
            Sleep(500);
            dllWait++;
        }
    }
    
    if (dllBase == NULL) {
        printf("[-] DLL not found after waiting\n");
        CloseHandle(hProcess);
        return 1;
    }
    
    printf("[+] Found %s at 0x%p (size: %lu bytes)\n", TARGET_DLL, dllBase, moduleSize);
    
    /* Give the DLL time to fully initialize */
    printf("[*] Waiting for DLL initialization...\n");
    Sleep(3000);
    
    /* Apply patches */
    int patchCount = PatchSSLVerification(hProcess, dllBase, moduleSize);
    
    CloseHandle(hProcess);
    
    if (patchCount > 0) {
        printf("\n[+] SUCCESS: Applied %d patches\n", patchCount);
        printf("[*] Try connecting to server now\n");
    } else {
        printf("\n[-] No patches applied\n");
    }
    
    printf("\n[*] Press Enter to exit...\n");
    getchar();
    
    return 0;
}
