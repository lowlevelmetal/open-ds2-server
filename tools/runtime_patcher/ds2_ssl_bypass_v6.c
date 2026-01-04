/*
 * Dead Space 2 SSL Certificate Verification Bypass v6
 * 
 * This patcher uses a different strategy: Instead of trying to patch the
 * high-level error handling, we patch the actual OpenSSL verification callback
 * to always return 1 (accept).
 * 
 * The embedded OpenSSL in activation.x86.dll has a verify callback that gets
 * called during SSL handshake. We need to find and patch it to always accept.
 * 
 * Strategy:
 * 1. Find functions that look like verify callbacks (take 2 params, return 0 or 1)
 * 2. Patch them to return 1
 * 3. Find where preverify_ok is tested and force it to be treated as success
 */

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <string.h>

#define TARGET_PROCESS "deadspace2.exe"
#define TARGET_DLL "activation.x86.dll"

DWORD FindProcessByName(const char* name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(pe);
    
    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, name) == 0) {
                CloseHandle(snap);
                return pe.th32ProcessID;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return 0;
}

BYTE* FindDllBase(HANDLE hProcess, const char* dllName, DWORD* outSize) {
    HMODULE mods[1024];
    DWORD needed;
    
    if (!EnumProcessModules(hProcess, mods, sizeof(mods), &needed))
        return NULL;
    
    for (DWORD i = 0; i < needed / sizeof(HMODULE); i++) {
        char modName[MAX_PATH];
        if (GetModuleFileNameExA(hProcess, mods[i], modName, MAX_PATH)) {
            char* baseName = strrchr(modName, '\\');
            baseName = baseName ? baseName + 1 : modName;
            
            if (_stricmp(baseName, dllName) == 0) {
                MODULEINFO mi;
                if (GetModuleInformation(hProcess, mods[i], &mi, sizeof(mi))) {
                    *outSize = mi.SizeOfImage;
                    return (BYTE*)mi.lpBaseOfDll;
                }
            }
        }
    }
    return NULL;
}

int PatchMemory(HANDLE hProcess, BYTE* addr, BYTE* patch, SIZE_T len) {
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, addr, len, PAGE_EXECUTE_READWRITE, &oldProtect))
        return 0;
    SIZE_T written;
    int result = WriteProcessMemory(hProcess, addr, patch, len, &written) && written == len;
    VirtualProtectEx(hProcess, addr, len, oldProtect, &oldProtect);
    return result;
}

int main() {
    printf("=== Dead Space 2 SSL Bypass v6 ===\n");
    printf("Strategy: Patch SSL verify callback return values\n\n");
    
    DWORD pid = FindProcessByName(TARGET_PROCESS);
    if (!pid) {
        printf("[-] Dead Space 2 not running\n");
        return 1;
    }
    printf("[+] Found Dead Space 2 (PID: %lu)\n", pid);
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Cannot open process\n");
        return 1;
    }
    
    DWORD dllSize = 0;
    BYTE* dllBase = FindDllBase(hProcess, TARGET_DLL, &dllSize);
    if (!dllBase) {
        printf("[-] Cannot find %s\n", TARGET_DLL);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Found %s at 0x%p, size=0x%lx\n", TARGET_DLL, dllBase, dllSize);
    
    // Read the entire DLL into memory
    BYTE* buffer = VirtualAlloc(NULL, dllSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buffer) {
        printf("[-] Cannot allocate memory\n");
        CloseHandle(hProcess);
        return 1;
    }
    
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, dllBase, buffer, dllSize, &bytesRead)) {
        printf("[-] Cannot read process memory\n");
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[*] Read %zu bytes from process memory\n\n", bytesRead);
    
    int patchCount = 0;
    
    /*
     * Looking at the disassembly, the error handling at 0x795e5cd3 checks
     * various error codes and returns -1 for most. We need to patch it to
     * return 1 instead.
     * 
     * At 0x795e5cfc: or eax,0xffffffff ; ret
     * This sets eax to -1 (0xFFFFFFFF)
     * 
     * We want to change this to: mov eax, 1 ; ret
     * Which is: B8 01 00 00 00 C3
     * 
     * But the original is: 83 C8 FF (or eax, -1) + E8 xx xx xx xx (call) + C3 (ret)
     * We need to replace starting from 0x5cfc
     * 
     * Original bytes at 0x5cfc: 83 c8 ff e8 11 f3 ff ff c3
     * New bytes: B8 01 00 00 00 90 90 90 C3 (mov eax, 1; nop; nop; nop; ret)
     */
    
    printf("[*] Looking for X509 error handler return path...\n");
    
    // Pattern at offset 0x5cfc relative to function at 0x5ac5
    // Full pattern context: 83 c8 ff e8 xx xx xx xx c3
    // "or eax, 0xffffffff; call xxx; ret"
    BYTE pattern1[] = { 0x83, 0xc8, 0xff, 0xe8 };
    
    for (DWORD i = 0x5c00; i < 0x5e00 && i < bytesRead - 10; i++) {
        if (memcmp(buffer + i, pattern1, sizeof(pattern1)) == 0) {
            // Check if there's a ret (0xc3) within the next 10 bytes
            for (int j = 4; j < 15 && i + j < bytesRead; j++) {
                if (buffer[i + j] == 0xc3) {
                    printf("[+] Found return -1 pattern at offset 0x%lx\n", i);
                    printf("    Context: ");
                    for (int k = 0; k < 15 && i + k < bytesRead; k++)
                        printf("%02x ", buffer[i + k]);
                    printf("\n");
                    
                    // Patch: mov eax, 1; nop padding; ret
                    // We need to fill up to the ret instruction
                    BYTE patch[16];
                    patch[0] = 0xB8; // mov eax, imm32
                    patch[1] = 0x01; // 1
                    patch[2] = 0x00;
                    patch[3] = 0x00;
                    patch[4] = 0x00;
                    int patchLen = 5;
                    // Fill NOPs until ret
                    while (patchLen < j) {
                        patch[patchLen++] = 0x90;
                    }
                    patch[patchLen++] = 0xC3; // ret
                    
                    BYTE* target = dllBase + i;
                    if (PatchMemory(hProcess, target, patch, patchLen)) {
                        printf("    [+] Patched to return 1 at 0x%p\n", target);
                        patchCount++;
                    }
                    break;
                }
            }
        }
    }
    
    /*
     * Also patch the places where error codes cause rejection
     * The jumps to 0x5bbf are the "reject" paths
     * 
     * At 0x5af2: 0f 84 c7 00 00 00  -> JE to reject (error == 2)
     * At 0x5afb: 0f 84 be 00 00 00  -> JE to reject (error == 0x15)
     * At 0x5b04: 0f 84 b5 00 00 00  -> JE to reject (error == 0x16)
     * At 0x5b0d: 0f 84 ac 00 00 00  -> JE to reject (error == 6)
     * At 0x5b16: 0f 84 a3 00 00 00  -> JE to reject (error == 0xf)
     * 
     * We should NOP these jumps so they fall through
     */
    
    printf("\n[*] Looking for reject path jumps to NOP...\n");
    
    // Look for the function prologue first
    // 6a 10 68 c8 5e 67 79 (push 0x10; push 0x79675ec8)
    BYTE funcPrologue[] = { 0x6a, 0x10, 0x68, 0xc8, 0x5e, 0x67, 0x79 };
    DWORD funcOffset = 0;
    
    for (DWORD i = 0; i < bytesRead - sizeof(funcPrologue); i++) {
        if (memcmp(buffer + i, funcPrologue, sizeof(funcPrologue)) == 0) {
            funcOffset = i;
            printf("[+] Found X509 handler function at offset 0x%lx\n", i);
            break;
        }
    }
    
    if (funcOffset > 0) {
        // The reject jumps are at known offsets from the function start
        // Function at 0x5ac5, reject jumps at:
        // 0x5af2 (offset 0x2d), 0x5afb (0x36), 0x5b04 (0x3f), 0x5b0d (0x48), 0x5b16 (0x51)
        
        struct {
            DWORD offset; // from func start
            BYTE expected[4]; // first 4 bytes of JE
        } rejectJumps[] = {
            { 0x2d, { 0x0f, 0x84, 0xc7, 0x00 } },
            { 0x36, { 0x0f, 0x84, 0xbe, 0x00 } },
            { 0x3f, { 0x0f, 0x84, 0xb5, 0x00 } },
            { 0x48, { 0x0f, 0x84, 0xac, 0x00 } },
            { 0x51, { 0x0f, 0x84, 0xa3, 0x00 } },
        };
        
        BYTE nops6[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
        
        for (int i = 0; i < 5; i++) {
            DWORD offset = funcOffset + rejectJumps[i].offset;
            if (offset + 6 < bytesRead && 
                memcmp(buffer + offset, rejectJumps[i].expected, 4) == 0) {
                printf("    Found reject JE at offset 0x%lx\n", offset);
                if (PatchMemory(hProcess, dllBase + offset, nops6, 6)) {
                    printf("    [+] NOPed JE at 0x%p\n", dllBase + offset);
                    patchCount++;
                }
            }
        }
        
        // Also NOP the final JNE at offset 0x64 (0x5b29)
        // 0f 85 a4 01 00 00
        DWORD jneOffset = funcOffset + 0x64;
        BYTE jneExpected[] = { 0x0f, 0x85, 0xa4, 0x01 };
        if (jneOffset + 6 < bytesRead && memcmp(buffer + jneOffset, jneExpected, 4) == 0) {
            printf("    Found final JNE at offset 0x%lx\n", jneOffset);
            if (PatchMemory(hProcess, dllBase + jneOffset, nops6, 6)) {
                printf("    [+] NOPed JNE at 0x%p\n", dllBase + jneOffset);
                patchCount++;
            }
        }
    }
    
    /*
     * Alternative approach: Patch the actual SSL_CTX_set_verify callback
     * In OpenSSL, when verification fails, the callback is called with
     * preverify_ok = 0. We need to find where this is checked and make
     * the code treat it as if preverify_ok = 1.
     * 
     * Looking for pattern: "test/cmp [ebp+8], 0/1" followed by JE/JNE
     */
    
    printf("\n[*] Looking for preverify_ok checks...\n");
    
    // Pattern: 83 7d 08 00 (cmp dword [ebp+8], 0) followed by conditional jump
    // or: 83 7d 08 01 (cmp dword [ebp+8], 1)
    for (DWORD i = 0; i < bytesRead - 10; i++) {
        // Check for: cmp [ebp+8], 0; je/jne ...
        if (buffer[i] == 0x83 && buffer[i+1] == 0x7d && 
            buffer[i+2] == 0x08 && buffer[i+3] == 0x00) {
            // Check if followed by JE (74/0f84) or JNE (75/0f85)
            if (buffer[i+4] == 0x74 || buffer[i+4] == 0x75 ||
                (buffer[i+4] == 0x0f && (buffer[i+5] == 0x84 || buffer[i+5] == 0x85))) {
                printf("    Found 'cmp [ebp+8], 0' at offset 0x%lx: ", i);
                for (int j = 0; j < 10; j++)
                    printf("%02x ", buffer[i+j]);
                printf("\n");
            }
        }
        
        // Also check: test [ebp+8], 1 pattern
        if (buffer[i] == 0xf6 && buffer[i+1] == 0x45 &&
            buffer[i+2] == 0x08 && buffer[i+3] == 0x01) {
            printf("    Found 'test [ebp+8], 1' at offset 0x%lx: ", i);
            for (int j = 0; j < 10; j++)
                printf("%02x ", buffer[i+j]);
            printf("\n");
        }
    }
    
    VirtualFree(buffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    printf("\n");
    printf("Patches applied: %d\n", patchCount);
    if (patchCount > 0) {
        printf("[+] Patches applied. Try connecting to the server now.\n");
    } else {
        printf("[-] No patches were applied.\n");
    }
    
    return patchCount > 0 ? 0 : 1;
}
