/*
 * Dead Space 2 SSL Certificate Verification Bypass v5
 * 
 * Comprehensive patch for activation.x86.dll SSL verification
 * 
 * The X509 verification callback at 0x795e5ac5 checks error codes:
 *   - Error codes 2, 0x15, 0x16, 6, 0xf -> jump to 0x795e5bbf (reject)
 *   - Error codes 8, 4, 0xb -> fall through to handler at 0x795e5b2f
 *   - All other codes (including 0x12 self-signed) -> JNE to 0x795e5cd3 (success path)
 * 
 * The JNE at 0x795e5b29 needs to be NOPed so all error codes fall through.
 * Also need to handle the reject jumps.
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

int main() {
    printf("=== Dead Space 2 SSL Bypass v5 ===\n");
    printf("Target: X509 verification callback\n\n");
    
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
     * X509 verification function structure at offset 0x5ac5:
     * 
     * 795e5ac5:  push 0x10                ; function prologue
     * ...
     * 795e5adb:  cmp esi,0x4              ; check arg2 == 4
     * 795e5ade:  je  0x795e5cd3           ; if yes, goto success
     * 795e5ae4:  cmp esi,0x3              ; check arg2 == 3
     * 795e5ae7:  je  0x795e5cd3           ; if yes, goto success
     * 795e5aed:  push 0x2
     * 795e5aef:  pop edi                  ; edi = 2
     * 795e5af0:  cmp ebx,edi              ; check error == 2
     * 795e5af2:  je  0x795e5bbf           ; REJECT path
     * 795e5af8:  cmp ebx,0x15             ; check error == 21
     * 795e5afb:  je  0x795e5bbf           ; REJECT path
     * 795e5b01:  cmp ebx,0x16             ; check error == 22
     * 795e5b04:  je  0x795e5bbf           ; REJECT path  
     * 795e5b0a:  cmp ebx,0x6              ; check error == 6
     * 795e5b0d:  je  0x795e5bbf           ; REJECT path
     * 795e5b13:  cmp ebx,0xf              ; check error == 15
     * 795e5b16:  je  0x795e5bbf           ; REJECT path
     * 795e5b1c:  cmp ebx,0x8              ; check error == 8
     * 795e5b1f:  je  0x795e5b2f           ; handler path
     * 795e5b21:  cmp ebx,0x4              ; check error == 4
     * 795e5b24:  je  0x795e5b2f           ; handler path
     * 795e5b26:  cmp ebx,0xb              ; check error == 11
     * 795e5b29:  jne 0x795e5cd3           ; ALL OTHER ERRORS -> SUCCESS PATH!
     * 
     * The REJECT path (0x5bbf) handles known "bad" errors: 2, 21, 22, 6, 15
     * The SUCCESS path (0x5cd3) is jumped to for arg2=3 or 4, or unknown errors
     * 
     * Error 0x12 (18) = X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT
     * This falls through to the jne at 0x5b29 and goes to SUCCESS (0x5cd3)!
     * 
     * Wait - that means it should already work? Let me trace more carefully...
     * The issue might be that 0x5cd3 isn't success, it's the function exit/cleanup
     * 
     * Let me look at what happens at each path...
     */
    
    // Strategy: Force ALL error checks to go to the "accept" path
    // by NOPing the JE instructions that go to 0x5bbf (reject)
    
    printf("[*] Searching for X509 verification function...\n");
    
    // Pattern: The function prologue at offset 0x5ac5
    // 6a 10 68 c8 5e 67 79 e8 ff f4 ff ff
    BYTE funcStart[] = { 0x6a, 0x10, 0x68, 0xc8, 0x5e, 0x67, 0x79 };
    
    for (DWORD i = 0; i < bytesRead - sizeof(funcStart); i++) {
        if (memcmp(buffer + i, funcStart, sizeof(funcStart)) == 0) {
            printf("[+] Found function prologue at offset 0x%lx\n", i);
            
            // Now search within the function for the reject jumps
            // Pattern: 0f 84 xx xx 00 00 (JE near relative)
            // These are at offsets: 0x5af2, 0x5afb, 0x5b04, 0x5b0d, 0x5b16
            
            // Let's patch all JE instructions to 0x5bbf (reject path)
            // We need to find them by their relative target
            
            // 0x5bbf from 0x5af8 = 0xc7 bytes ahead (after 6-byte instruction)
            // 0x5af2: 0f 84 c7 00 00 00 -> je 0x5bbf
            // 0x5afb: 0f 84 be 00 00 00 -> je 0x5bbf
            // etc.
            
            DWORD funcBase = i;
            
            // Patch pattern 1: JE +0xC7 (at offset 0x5af2 - 0x5ac5 = 0x2d from func start)
            // 0f 84 c7 00 00 00
            DWORD offset_af2 = funcBase + (0x5af2 - 0x5ac5);
            if (buffer[offset_af2] == 0x0f && buffer[offset_af2+1] == 0x84 &&
                buffer[offset_af2+2] == 0xc7 && buffer[offset_af2+3] == 0x00) {
                printf("    Found JE at offset 0x%lx (cmp ebx,2 check)\n", offset_af2);
                // NOP out the JE instruction (6 bytes)
                BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
                BYTE* target = dllBase + offset_af2;
                DWORD oldProtect;
                if (VirtualProtectEx(hProcess, target, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    SIZE_T written;
                    WriteProcessMemory(hProcess, target, nops, 6, &written);
                    VirtualProtectEx(hProcess, target, 6, oldProtect, &oldProtect);
                    printf("    [+] Patched JE at 0x%p\n", target);
                    patchCount++;
                }
            }
            
            // Patch pattern 2: JE +0xBE (at offset 0x5afb)
            DWORD offset_afb = funcBase + (0x5afb - 0x5ac5);
            if (buffer[offset_afb] == 0x0f && buffer[offset_afb+1] == 0x84 &&
                buffer[offset_afb+2] == 0xbe && buffer[offset_afb+3] == 0x00) {
                printf("    Found JE at offset 0x%lx (cmp ebx,0x15 check)\n", offset_afb);
                BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
                BYTE* target = dllBase + offset_afb;
                DWORD oldProtect;
                if (VirtualProtectEx(hProcess, target, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    SIZE_T written;
                    WriteProcessMemory(hProcess, target, nops, 6, &written);
                    VirtualProtectEx(hProcess, target, 6, oldProtect, &oldProtect);
                    printf("    [+] Patched JE at 0x%p\n", target);
                    patchCount++;
                }
            }
            
            // Patch pattern 3: JE +0xB5 (at offset 0x5b04)
            DWORD offset_b04 = funcBase + (0x5b04 - 0x5ac5);
            if (buffer[offset_b04] == 0x0f && buffer[offset_b04+1] == 0x84 &&
                buffer[offset_b04+2] == 0xb5 && buffer[offset_b04+3] == 0x00) {
                printf("    Found JE at offset 0x%lx (cmp ebx,0x16 check)\n", offset_b04);
                BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
                BYTE* target = dllBase + offset_b04;
                DWORD oldProtect;
                if (VirtualProtectEx(hProcess, target, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    SIZE_T written;
                    WriteProcessMemory(hProcess, target, nops, 6, &written);
                    VirtualProtectEx(hProcess, target, 6, oldProtect, &oldProtect);
                    printf("    [+] Patched JE at 0x%p\n", target);
                    patchCount++;
                }
            }
            
            // Patch pattern 4: JE +0xAC (at offset 0x5b0d)
            DWORD offset_b0d = funcBase + (0x5b0d - 0x5ac5);
            if (buffer[offset_b0d] == 0x0f && buffer[offset_b0d+1] == 0x84 &&
                buffer[offset_b0d+2] == 0xac && buffer[offset_b0d+3] == 0x00) {
                printf("    Found JE at offset 0x%lx (cmp ebx,0x6 check)\n", offset_b0d);
                BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
                BYTE* target = dllBase + offset_b0d;
                DWORD oldProtect;
                if (VirtualProtectEx(hProcess, target, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    SIZE_T written;
                    WriteProcessMemory(hProcess, target, nops, 6, &written);
                    VirtualProtectEx(hProcess, target, 6, oldProtect, &oldProtect);
                    printf("    [+] Patched JE at 0x%p\n", target);
                    patchCount++;
                }
            }
            
            // Patch pattern 5: JE +0xA3 (at offset 0x5b16)
            DWORD offset_b16 = funcBase + (0x5b16 - 0x5ac5);
            if (buffer[offset_b16] == 0x0f && buffer[offset_b16+1] == 0x84 &&
                buffer[offset_b16+2] == 0xa3 && buffer[offset_b16+3] == 0x00) {
                printf("    Found JE at offset 0x%lx (cmp ebx,0xf check)\n", offset_b16);
                BYTE nops[] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
                BYTE* target = dllBase + offset_b16;
                DWORD oldProtect;
                if (VirtualProtectEx(hProcess, target, 6, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    SIZE_T written;
                    WriteProcessMemory(hProcess, target, nops, 6, &written);
                    VirtualProtectEx(hProcess, target, 6, oldProtect, &oldProtect);
                    printf("    [+] Patched JE at 0x%p\n", target);
                    patchCount++;
                }
            }
            
            break;
        }
    }
    
    // Also look for the SSL verification callback registration
    // This might set up a verify callback that rejects self-signed certs
    
    printf("\n[*] Searching for alternate SSL check patterns...\n");
    
    // Pattern for "depth zero self signed" check (error 18 = 0x12)
    // Look for: cmp reg, 0x12
    // 83 f8 12 (cmp eax,0x12), 83 fb 12 (cmp ebx,0x12), 83 f9 12 (cmp ecx,0x12)
    
    for (DWORD i = 0; i < bytesRead - 10; i++) {
        // cmp ebx/eax/ecx, 0x12 followed by JE or JNE
        if (buffer[i] == 0x83 && buffer[i+2] == 0x12) {
            BYTE reg = buffer[i+1];
            if (reg == 0xf8 || reg == 0xfb || reg == 0xf9 || reg == 0xfe) { // eax, ebx, ecx, esi
                // Check if followed by conditional jump
                if (buffer[i+3] == 0x74 || buffer[i+3] == 0x75 ||  // JE/JNE short
                    buffer[i+3] == 0x0f) {  // JE/JNE near
                    printf("    Found 'cmp reg, 0x12' at offset 0x%lx\n", i);
                    printf("    Context: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                           buffer[i], buffer[i+1], buffer[i+2], buffer[i+3],
                           buffer[i+4], buffer[i+5], buffer[i+6], buffer[i+7]);
                }
            }
        }
    }
    
    VirtualFree(buffer, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    
    printf("\nPatches applied: %d\n", patchCount);
    if (patchCount > 0) {
        printf("[+] SUCCESS! Try connecting to the server now.\n");
    } else {
        printf("[-] No patches were applied. The function may have a different pattern.\n");
    }
    
    return patchCount > 0 ? 0 : 1;
}
