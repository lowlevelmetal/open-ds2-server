/*
 * Dead Space 2 SSL Patcher v6 - Precise Surgical Patch
 * 
 * Based on actual disassembly analysis of activation.x86.dll:
 * 
 * At 0x795ebdff (file offset 0xadff relative to .text section start):
 *   c7 86 30 01 00 00 01 00 00 00    mov DWORD PTR [esi+0x130], 0x1
 * 
 * This sets SSL verify_mode to SSL_VERIFY_PEER (1).
 * We change it to SSL_VERIFY_NONE (0):
 *   c7 86 30 01 00 00 00 00 00 00    mov DWORD PTR [esi+0x130], 0x0
 * 
 * The DLL is loaded at 0x795e0000, so:
 *   Instruction at 0x795ebdff = base + 0xbdff
 *   The byte to change is at 0x795ebe05 = base + 0xbe05 (the 0x01)
 * 
 * Also patching similar locations at:
 *   0x795ec2fc: mov DWORD PTR [edx+0x130], 0x1 (c7 82 30 01 00 00 01...)
 * 
 * Build: i686-w64-mingw32-gcc -o ds2_ssl_patcher_v6.exe ds2_ssl_patcher_v6.c -lpsapi -static -O2
 */

#include <windows.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <string.h>

#define GAME_EXE "deadspace2.exe"
#define TARGET_DLL "activation.x86.dll"

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

int main(int argc, char* argv[]) {
    printf("===========================================\n");
    printf(" Dead Space 2 SSL Patcher v6\n");
    printf(" Precise Surgical Verification Bypass\n");
    printf("===========================================\n\n");
    
    DWORD pid = FindProcess(GAME_EXE);
    if (pid == 0) {
        printf("[-] %s not found. Start the game first.\n", GAME_EXE);
        printf("[*] Press Enter to exit...\n");
        getchar();
        return 1;
    }
    
    printf("[+] Found process: PID %lu\n", pid);
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Failed to open process (error %lu)\n", GetLastError());
        printf("    Try running as Administrator\n");
        getchar();
        return 1;
    }
    
    DWORD moduleSize = 0;
    BYTE* dllBase = FindModuleBase(hProcess, TARGET_DLL, &moduleSize);
    
    if (dllBase == NULL) {
        printf("[-] %s not found in process\n", TARGET_DLL);
        CloseHandle(hProcess);
        getchar();
        return 1;
    }
    
    printf("[+] Found %s at 0x%p (size: %lu bytes)\n", TARGET_DLL, dllBase, moduleSize);
    
    /* Read module into memory for verification */
    printf("[*] Reading module memory...\n");
    BYTE* moduleData = (BYTE*)malloc(moduleSize);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, dllBase, moduleData, moduleSize, &bytesRead)) {
        printf("[-] Failed to read module memory\n");
        free(moduleData);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Read %zu bytes\n", bytesRead);
    
    int totalPatches = 0;
    
    /* ============================================================
     * PATCH 1: Primary verify_mode = 1 instruction
     * 
     * Location: 0xbdff relative to module base
     * Pattern: c7 86 30 01 00 00 01 00 00 00
     *          mov DWORD PTR [esi+0x130], 0x1
     * 
     * We change the 01 at offset 0xbe05 to 00
     * ============================================================ */
    printf("\n[*] Patch 1: Primary verify_mode setter at +0xbdff...\n");
    
    SIZE_T offset1 = 0xbdff;
    /* Expected pattern: c7 86 30 01 00 00 01 00 00 00 */
    BYTE expected1[] = {0xc7, 0x86, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    
    if (offset1 + 10 <= bytesRead && memcmp(moduleData + offset1, expected1, 10) == 0) {
        printf("    Found pattern at +0x%zX\n", offset1);
        /* Change byte at offset1+6 from 0x01 to 0x00 */
        BYTE newVal = 0x00;
        if (WriteMem(hProcess, dllBase + offset1 + 6, &newVal, 1)) {
            printf("    [+] Patched verify_mode = 0\n");
            totalPatches++;
        }
    } else {
        printf("    Pattern not found at expected location, searching...\n");
        /* Search for the pattern */
        for (SIZE_T i = 0; i < bytesRead - 10; i++) {
            if (memcmp(moduleData + i, expected1, 10) == 0) {
                printf("    Found pattern at +0x%zX\n", i);
                BYTE newVal = 0x00;
                if (WriteMem(hProcess, dllBase + i + 6, &newVal, 1)) {
                    printf("    [+] Patched verify_mode = 0\n");
                    totalPatches++;
                }
            }
        }
    }
    
    /* ============================================================
     * PATCH 2: Secondary verify_mode = 1 instruction
     * 
     * Location: 0xc2fc relative to module base
     * Pattern: c7 82 30 01 00 00 01 00 00 00
     *          mov DWORD PTR [edx+0x130], 0x1
     * ============================================================ */
    printf("\n[*] Patch 2: Secondary verify_mode setter at +0xc2fc...\n");
    
    SIZE_T offset2 = 0xc2fc;
    BYTE expected2[] = {0xc7, 0x82, 0x30, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00};
    
    if (offset2 + 10 <= bytesRead && memcmp(moduleData + offset2, expected2, 10) == 0) {
        printf("    Found pattern at +0x%zX\n", offset2);
        BYTE newVal = 0x00;
        if (WriteMem(hProcess, dllBase + offset2 + 6, &newVal, 1)) {
            printf("    [+] Patched verify_mode = 0\n");
            totalPatches++;
        }
    } else {
        printf("    Pattern not found at expected location, searching...\n");
        for (SIZE_T i = 0; i < bytesRead - 10; i++) {
            if (memcmp(moduleData + i, expected2, 10) == 0) {
                printf("    Found pattern at +0x%zX\n", i);
                BYTE newVal = 0x00;
                if (WriteMem(hProcess, dllBase + i + 6, &newVal, 1)) {
                    printf("    [+] Patched verify_mode = 0\n");
                    totalPatches++;
                }
            }
        }
    }
    
    /* ============================================================
     * PATCH 3: Search for all mov [reg+0x130], 1 patterns
     * 
     * These are: c7 8X 30 01 00 00 01 00 00 00
     * where X varies based on register
     * ============================================================ */
    printf("\n[*] Patch 3: Searching for all verify_mode=1 patterns...\n");
    
    int modePatches = 0;
    for (SIZE_T i = 0; i < bytesRead - 10; i++) {
        /* mov dword ptr [reg+0x130], 1 */
        if (moduleData[i] == 0xc7 &&
            (moduleData[i+1] & 0xf8) == 0x80 &&  /* ModR/M for [reg+disp32] */
            moduleData[i+2] == 0x30 && 
            moduleData[i+3] == 0x01 &&
            moduleData[i+4] == 0x00 && 
            moduleData[i+5] == 0x00 &&
            moduleData[i+6] == 0x01 &&
            moduleData[i+7] == 0x00 &&
            moduleData[i+8] == 0x00 &&
            moduleData[i+9] == 0x00) {
            
            printf("    Found verify_mode=1 at +0x%zX\n", i);
            BYTE newVal = 0x00;
            if (WriteMem(hProcess, dllBase + i + 6, &newVal, 1)) {
                modePatches++;
            }
        }
    }
    printf("[+] Patched %d verify_mode=1 instructions\n", modePatches);
    totalPatches += modePatches;
    
    /* ============================================================
     * PATCH 4: Patch the conditional jump that decides to verify
     * 
     * At 0xbdfd: 74 14  je 0x795ebe13 (skip if arg is 0)
     *            85 c0  test eax, eax
     * 
     * If we NOP the test and change je to jmp, we always skip verify
     * Actually easier: Change jne to jmp at the inverse location
     * 
     * Better: The code at 0xbdfb checks if argument is 0:
     *   test eax, eax
     *   je skip_verify
     * 
     * We want it to ALWAYS skip verify, so change je to jmp
     * ============================================================ */
    printf("\n[*] Patch 4: Force skip verification branch...\n");
    
    SIZE_T offset4 = 0xbdfb;  /* test eax, eax */
    if (moduleData[offset4] == 0x85 && moduleData[offset4+1] == 0xc0 &&
        moduleData[offset4+2] == 0x74) {  /* je short */
        printf("    Found conditional at +0x%zX\n", offset4);
        /* Change je (0x74) to jmp (0xEB) */
        BYTE jmpShort = 0xEB;
        if (WriteMem(hProcess, dllBase + offset4 + 2, &jmpShort, 1)) {
            printf("    [+] Changed je to jmp (always skip verify)\n");
            totalPatches++;
        }
    } else {
        printf("    Conditional not found at expected location\n");
    }
    
    /* ============================================================
     * PATCH 5: Patch similar pattern in other SSL setup functions
     * 
     * At 0xbc94: 89 87 30 01 00 00  mov [edi+0x130], eax
     * Here eax is the result of a check. We want eax=0.
     * Precede with: 31 c0 (xor eax, eax) by finding space
     * 
     * Actually, let's just search for mov [reg+0x130], eax patterns
     * and see if we can NOP them
     * ============================================================ */
    printf("\n[*] Patch 5: NOP verify_mode stores from eax...\n");
    
    int nopPatches = 0;
    /* Pattern: 89 8X 30 01 00 00 (mov [reg+0x130], eax/ecx/edx/ebx) */
    for (SIZE_T i = 0; i < bytesRead - 6; i++) {
        if (moduleData[i] == 0x89 &&
            (moduleData[i+1] & 0xf8) == 0x80 &&  /* ModR/M for [reg+disp32] from e?x */
            moduleData[i+2] == 0x30 && 
            moduleData[i+3] == 0x01 &&
            moduleData[i+4] == 0x00 && 
            moduleData[i+5] == 0x00) {
            
            printf("    Found mov [reg+0x130], reg at +0x%zX\n", i);
            /* NOP out the instruction */
            BYTE nops[6] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
            if (WriteMem(hProcess, dllBase + i, nops, 6)) {
                nopPatches++;
            }
        }
    }
    printf("[+] NOPed %d verify_mode stores\n", nopPatches);
    totalPatches += nopPatches;
    
    /* ============================================================
     * PATCH 6: Search for the X509 verify result handler
     * 
     * Looking for the callback that handles X509_V_ERR codes
     * At 0x5af8 and 0x5bcf: cmp ebx, 0x15 (check for error 21)
     * 
     * Error 21 = X509_V_ERR_UNABLE_TO_VERIFY_LEAF_SIGNATURE
     * Error 20 = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY  
     * Error 2 = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT
     * 
     * These jumps go to error handler. We NOP them out.
     * ============================================================ */
    printf("\n[*] Patch 6: Bypass X509 error code checks...\n");
    
    /* At 0x5af8: 83 fb 15  cmp ebx, 0x15
     *            0f 84 be 00 00 00  je [error_handler]
     */
    int errPatches = 0;
    for (SIZE_T i = 0; i < bytesRead - 10; i++) {
        /* cmp ebx, 0x15; je ... */
        if (moduleData[i] == 0x83 && moduleData[i+1] == 0xfb && 
            moduleData[i+2] == 0x15 &&  /* cmp ebx, 0x15 */
            moduleData[i+3] == 0x0f && moduleData[i+4] == 0x84) {  /* je near */
            
            printf("    Found X509 error 21 check at +0x%zX\n", i);
            /* NOP the je (6 bytes starting at i+3) */
            BYTE nops[6] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
            if (WriteMem(hProcess, dllBase + i + 3, nops, 6)) {
                errPatches++;
            }
        }
        
        /* cmp ebx, 0x02; je ... (X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT) */
        if (moduleData[i] == 0x3b && moduleData[i+1] == 0xdf &&  /* cmp ebx, edi (where edi=2) */
            moduleData[i+2] == 0x0f && moduleData[i+3] == 0x84) {  /* je near */
            
            printf("    Found X509 error 2 check at +0x%zX\n", i);
            BYTE nops[6] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
            if (WriteMem(hProcess, dllBase + i + 2, nops, 6)) {
                errPatches++;
            }
        }
    }
    printf("[+] Bypassed %d X509 error checks\n", errPatches);
    totalPatches += errPatches;
    
    free(moduleData);
    CloseHandle(hProcess);
    
    printf("\n===========================================\n");
    printf("[*] Total patches applied: %d\n", totalPatches);
    
    if (totalPatches > 0) {
        printf("[+] SUCCESS: Certificate verification disabled\n");
        printf("[*] Try connecting to server now\n");
    } else {
        printf("[-] No patches applied - patterns may have changed\n");
    }
    
    printf("\n[*] Press Enter to exit...\n");
    getchar();
    
    return 0;
}
