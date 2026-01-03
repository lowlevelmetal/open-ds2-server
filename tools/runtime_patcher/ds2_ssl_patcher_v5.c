/*
 * Dead Space 2 SSL Patcher v5 - Force SSL_VERIFY_NONE
 * 
 * This version focuses on forcing verify_mode to 0 (SSL_VERIFY_NONE)
 * at the actual storage locations, rather than patching error handling.
 * 
 * Key insight: We found 3 locations where verify_mode is stored:
 *   mov [edi+0x130], eax at offsets 0xB094, 0xBC94, 0xC3F4
 * 
 * We need to ensure eax=0 before these stores, or change them to store 0 directly.
 * 
 * Build: i686-w64-mingw32-gcc -o ds2_ssl_patcher_v5.exe ds2_ssl_patcher_v5.c -lpsapi -static -O2
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
    
    /* ============================================================
     * PATCH 1: Force verify_mode stores to always store 0
     * 
     * Pattern: 89 87 30 01 00 00 (mov [edi+0x130], eax)
     * We insert: 31 C0 (xor eax, eax) before it
     * 
     * But we can't just insert bytes. Instead, we look for the
     * instruction before and modify the whole sequence.
     * 
     * Alternative: Change to C7 87 30 01 00 00 00 00 00 00
     *              (mov dword ptr [edi+0x130], 0)
     * This is 10 bytes vs 6, so we need to find space.
     * 
     * Safest: Find the 'test eax, eax' or 'cmp' before the store
     * and NOP it + change to store 0.
     * ============================================================ */
    printf("\n[*] Patch 1: Force verify_mode to SSL_VERIFY_NONE...\n");
    
    /* Known offsets from analysis: 0xB094, 0xBC94, 0xC3F4 */
    SIZE_T verifyModeOffsets[] = {0xB094, 0xBC94, 0xC3F4};
    int numOffsets = sizeof(verifyModeOffsets) / sizeof(verifyModeOffsets[0]);
    
    for (int i = 0; i < numOffsets; i++) {
        SIZE_T offset = verifyModeOffsets[i];
        
        /* Verify the pattern is what we expect */
        if (offset + 6 <= bytesRead) {
            /* Should be: 89 87 30 01 00 00 */
            if (moduleData[offset] == 0x89 && moduleData[offset+1] == 0x87 &&
                moduleData[offset+2] == 0x30 && moduleData[offset+3] == 0x01) {
                
                printf("    Patching verify_mode store at offset 0x%zX\n", offset);
                
                /* Look backwards for xor eax, eax or test eax, eax we can modify */
                /* Or look for preceding instruction we can change */
                
                /* Check if there's room to insert xor eax,eax before */
                /* Look at bytes before: if there's a NOP or instruction we can overwrite */
                
                /* Strategy: Insert 31 C0 (xor eax, eax) by overwriting previous 2 bytes */
                /* But this is risky. Let's try a different approach: */
                
                /* Find where eax is set before this instruction and change it to xor eax,eax */
                BOOL foundPrecedingInstr = FALSE;
                for (int j = 1; j < 20 && offset >= j; j++) {
                    SIZE_T checkOffset = offset - j;
                    
                    /* Look for: mov eax, [xxx] (8B 05/07/45/etc) */
                    /* or: mov eax, ecx (8B C1) */
                    /* or any instruction that sets eax */
                    
                    /* If we find mov eax, xxx we can change it to xor eax, eax + nops */
                    if (moduleData[checkOffset] == 0x8B && 
                        (moduleData[checkOffset+1] & 0xF8) == 0xC0) {
                        /* mov eax, reg - 2 bytes */
                        printf("      Found 'mov eax, reg' at -0x%X, changing to 'xor eax, eax'\n", j);
                        BYTE xorEax[2] = {0x31, 0xC0};  /* xor eax, eax */
                        if (WriteMem(hProcess, dllBase + checkOffset, xorEax, 2)) {
                            totalPatches++;
                            foundPrecedingInstr = TRUE;
                        }
                        break;
                    }
                }
                
                if (!foundPrecedingInstr) {
                    /* Alternative: NOP out the store entirely */
                    /* This might break things, but let's try */
                    printf("      No preceding mov found, NOPing the store\n");
                    BYTE nops[6] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
                    if (WriteMem(hProcess, dllBase + offset, nops, 6)) {
                        totalPatches++;
                    }
                }
            } else {
                printf("    Pattern mismatch at offset 0x%zX (found: %02X %02X %02X %02X)\n", 
                       offset, moduleData[offset], moduleData[offset+1],
                       moduleData[offset+2], moduleData[offset+3]);
            }
        }
    }
    
    /* ============================================================
     * PATCH 2: Find and patch SSL_CTX_set_verify calls
     * 
     * Pattern: push mode (6A 01, 6A 02, or 6A 03); push something; call
     * Change: push mode -> push 0 (6A 00)
     * ============================================================ */
    printf("\n[*] Patch 2: Change SSL_CTX_set_verify mode to SSL_VERIFY_NONE...\n");
    
    int modePatches = 0;
    for (SIZE_T i = 0; i < bytesRead - 15; i++) {
        /* push 1, 2, or 3 (SSL_VERIFY modes) */
        if (moduleData[i] == 0x6A && 
            (moduleData[i+1] == 0x01 || moduleData[i+1] == 0x02 || moduleData[i+1] == 0x03)) {
            
            /* Look for a call within next 15 bytes */
            for (SIZE_T j = i + 2; j < i + 15 && j < bytesRead - 5; j++) {
                if (moduleData[j] == 0xE8) {  /* call rel32 */
                    /* This might be SSL_CTX_set_verify, change mode to 0 */
                    BYTE pushZero = 0x00;
                    if (WriteMem(hProcess, dllBase + i + 1, &pushZero, 1)) {
                        modePatches++;
                        if (modePatches <= 10) {
                            printf("    Changed push %d to push 0 at offset 0x%zX\n", 
                                   moduleData[i+1], i);
                        }
                    }
                    break;
                }
            }
        }
    }
    printf("[+] Changed %d verify mode pushes to 0\n", modePatches);
    totalPatches += modePatches;
    
    /* ============================================================
     * PATCH 3: Patch the verify callback registration
     * 
     * When verify_callback is stored (offset +0x134 typically),
     * we can NOP it out so no callback is registered
     * ============================================================ */
    printf("\n[*] Patch 3: Remove verify callback registration...\n");
    
    /* Pattern: 89 XX 34 01 00 00 (mov [reg+0x134], reg) */
    int callbackPatches = 0;
    for (SIZE_T i = 0; i < bytesRead - 10; i++) {
        if (moduleData[i] == 0x89 && 
            moduleData[i+2] == 0x34 && moduleData[i+3] == 0x01 &&
            moduleData[i+4] == 0x00 && moduleData[i+5] == 0x00) {
            
            printf("    Found callback store at offset 0x%zX\n", i);
            
            /* NOP it out */
            BYTE nops[6] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
            if (WriteMem(hProcess, dllBase + i, nops, 6)) {
                callbackPatches++;
            }
        }
    }
    printf("[+] NOPed %d callback registrations\n", callbackPatches);
    totalPatches += callbackPatches;
    
    /* ============================================================
     * PATCH 4: Find SSL_set_verify and patch similarly
     * 
     * SSL_set_verify(ssl, mode, callback) - same as CTX version
     * Offset in SSL struct might be different (+0x30 or similar)
     * ============================================================ */
    printf("\n[*] Patch 4: Patch SSL_set_verify mode stores...\n");
    
    /* Look for mov [reg+0x30], imm or mov [reg+0x30], reg where value is 1-3 */
    int sslSetVerifyPatches = 0;
    for (SIZE_T i = 0; i < bytesRead - 10; i++) {
        /* mov dword ptr [reg+0x30], imm8 sign-extended or small imm32 */
        /* C7 40 30 01 00 00 00 = mov [eax+0x30], 1 */
        if (moduleData[i] == 0xC7 && (moduleData[i+1] & 0xF8) == 0x40 &&
            moduleData[i+2] == 0x30) {
            
            DWORD value = *(DWORD*)(moduleData + i + 3);
            if (value >= 1 && value <= 3) {
                printf("    Found SSL verify_mode store at 0x%zX, value=%lu\n", i, value);
                /* Change value to 0 */
                BYTE zero = 0x00;
                if (WriteMem(hProcess, dllBase + i + 3, &zero, 1)) {
                    sslSetVerifyPatches++;
                }
            }
        }
    }
    printf("[+] Patched %d SSL verify_mode stores\n", sslSetVerifyPatches);
    totalPatches += sslSetVerifyPatches;
    
    /* ============================================================
     * PATCH 5: Hook the actual verification function
     * 
     * Find functions that look like X509_verify_cert or ssl_verify_cert_chain
     * and make them return 1 immediately
     * 
     * We look for functions that:
     * - Take 1 argument (X509_verify_cert) or 2 arguments (ssl_verify_cert_chain)
     * - Have complex logic inside
     * - Return 0 on failure
     * 
     * We change the function entry to: mov eax, 1; ret (B8 01 00 00 00 C3)
     * ============================================================ */
    printf("\n[*] Patch 5: Hook verification functions to return success...\n");
    
    /* Known good pattern for ssl_verify_cert_chain in OpenSSL 1.0.0:
     * It typically starts with: push ebp; mov ebp, esp; sub esp, XX; push ebx/esi/edi
     * And eventually calls X509_verify_cert
     * 
     * We look for functions that reference the error strings we found
     */
    
    /* For now, let's find specific patterns */
    /* X509_verify_cert in OpenSSL often has pattern at start: 
     * 55 8B EC 83 EC XX 53 56 57 ... followed by call to internal_verify
     */
    
    int hookPatches = 0;
    
    /* Pattern: push ebp; mov ebp, esp; sub esp, 0x20+; push registers; ...eventually returns 0 or 1 */
    /* We'll look for functions that are likely verify functions */
    
    /* Skip this aggressive approach for now - it might break things */
    
    printf("[+] Hooked %d verification functions\n", hookPatches);
    totalPatches += hookPatches;
    
    /* ============================================================
     * PATCH 6: Ensure all test eax,eax; jz/jne patterns after calls
     * are changed to always take the success path
     * 
     * This is what we did in v4, but more targeted
     * ============================================================ */
    printf("\n[*] Patch 6: Force success path after verify calls...\n");
    
    /* Find: call xxx; test eax,eax; jz error
     * Change jz to jmp (short) or NOP
     * 
     * But we need to be more selective - only patch if the call target
     * looks like a verify function
     */
    
    int pathPatches = 0;
    for (SIZE_T i = 5; i < bytesRead - 10; i++) {
        /* call rel32; test eax,eax; jz short */
        if (moduleData[i-5] == 0xE8 &&
            moduleData[i] == 0x85 && moduleData[i+1] == 0xC0 &&  /* test eax, eax */
            moduleData[i+2] == 0x74) {  /* jz short */
            
            /* Get the call target */
            int rel32 = *(int*)(moduleData + i - 4);
            SIZE_T callTarget = (i - 5 + 5 + rel32);  /* relative to this location */
            
            /* Check if call target is in valid range */
            if (callTarget < bytesRead) {
                /* Check if the target function looks like a verify function */
                /* It should have complexity and eventually return 0 or 1 */
                
                /* For now, only patch if the jump distance is significant (>= 10) */
                /* This suggests it's jumping to error handling */
                BYTE jmpDist = moduleData[i+3];
                if (jmpDist >= 10 && pathPatches < 50) {
                    /* Change jz to always fall through (NOP) */
                    BYTE nops[2] = {0x90, 0x90};
                    if (WriteMem(hProcess, dllBase + i + 2, nops, 2)) {
                        pathPatches++;
                    }
                }
            }
        }
        
        /* Also handle: call; test eax,eax; jnz success_continue */
        /* In this case we want jnz to always be taken */
        if (moduleData[i-5] == 0xE8 &&
            moduleData[i] == 0x85 && moduleData[i+1] == 0xC0 &&
            moduleData[i+2] == 0x75) {  /* jnz short */
            
            BYTE jmpDist = moduleData[i+3];
            if (jmpDist >= 5 && jmpDist <= 127 && pathPatches < 50) {
                /* Change jnz to jmp (unconditional) */
                BYTE jmpShort = 0xEB;
                if (WriteMem(hProcess, dllBase + i + 2, &jmpShort, 1)) {
                    pathPatches++;
                }
            }
        }
    }
    printf("[+] Forced %d success paths\n", pathPatches);
    totalPatches += pathPatches;
    
    free(moduleData);
    
    printf("\n[*] Total patches applied: %d\n", totalPatches);
    return totalPatches;
}

int main(int argc, char* argv[]) {
    printf("===========================================\n");
    printf(" Dead Space 2 SSL Patcher v5\n");
    printf(" Force SSL_VERIFY_NONE Approach\n");
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
