/*
 * Dead Space 2 SSL Bypass Patcher v4
 * 
 * FOCUSED APPROACH: Find and patch the X509 verification callback
 * 
 * The disassembly shows at file offset 0x4b26 (runtime addr varies):
 *   83 fb 0b        cmp ebx, 0xb
 *   0f 85 a4 01 00 00   jne fail_path
 * 
 * We need to NOP out the JNE so ALL X509 error codes are accepted.
 */

#include <windows.h>
#include <stdio.h>
#include <psapi.h>
#include <tlhelp32.h>

DWORD FindProcessByName(const char* processName) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;
    
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(pe32);
    
    if (Process32First(snapshot, &pe32)) {
        do {
            char lowerName[MAX_PATH];
            strncpy(lowerName, pe32.szExeFile, MAX_PATH);
            for (int i = 0; lowerName[i]; i++) {
                if (lowerName[i] >= 'A' && lowerName[i] <= 'Z')
                    lowerName[i] += 32;
            }
            
            if (strstr(lowerName, processName) != NULL) {
                CloseHandle(snapshot);
                return pe32.th32ProcessID;
            }
        } while (Process32Next(snapshot, &pe32));
    }
    
    CloseHandle(snapshot);
    return 0;
}

int PatchMemory(HANDLE hProcess, void* addr, void* newBytes, int len, const char* desc) {
    DWORD oldProtect;
    SIZE_T written;
    
    if (!VirtualProtectEx(hProcess, addr, len, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("    [-] VirtualProtect failed at %p: %lu\n", addr, GetLastError());
        return 0;
    }
    
    if (!WriteProcessMemory(hProcess, addr, newBytes, len, &written)) {
        printf("    [-] WriteProcessMemory failed at %p: %lu\n", addr, GetLastError());
        VirtualProtectEx(hProcess, addr, len, oldProtect, &oldProtect);
        return 0;
    }
    
    FlushInstructionCache(hProcess, addr, len);
    VirtualProtectEx(hProcess, addr, len, oldProtect, &oldProtect);
    
    printf("    [+] Patched at %p: %s\n", addr, desc);
    return 1;
}

int main() {
    printf("===========================================\n");
    printf("Dead Space 2 SSL Bypass Patcher v4\n");
    printf("Focused X509 callback patch\n");
    printf("===========================================\n\n");
    
    DWORD pid = FindProcessByName("deadspace2");
    if (!pid) {
        printf("[-] Dead Space 2 not running. Start the game first!\n");
        return 1;
    }
    printf("[+] Found Dead Space 2 (PID: %lu)\n", pid);
    
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProcess) {
        printf("[-] Could not open process: %lu\n", GetLastError());
        return 1;
    }
    
    HMODULE hMods[1024];
    DWORD cbNeeded;
    HMODULE hActivation = NULL;
    
    if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            char moduleName[MAX_PATH];
            if (GetModuleBaseNameA(hProcess, hMods[i], moduleName, sizeof(moduleName))) {
                for (int j = 0; moduleName[j]; j++) {
                    if (moduleName[j] >= 'A' && moduleName[j] <= 'Z')
                        moduleName[j] += 32;
                }
                
                if (strstr(moduleName, "activation") != NULL) {
                    hActivation = hMods[i];
                    printf("[+] Found %s at 0x%p\n", moduleName, hMods[i]);
                    break;
                }
            }
        }
    }
    
    if (!hActivation) {
        printf("[-] activation.x86.dll not found!\n");
        CloseHandle(hProcess);
        return 1;
    }
    
    MODULEINFO modInfo;
    if (!GetModuleInformation(hProcess, hActivation, &modInfo, sizeof(modInfo))) {
        printf("[-] Could not get module info\n");
        CloseHandle(hProcess);
        return 1;
    }
    
    unsigned char* base = (unsigned char*)modInfo.lpBaseOfDll;
    SIZE_T size = modInfo.SizeOfImage;
    printf("[*] Module: base=0x%p size=0x%lx\n\n", base, (unsigned long)size);
    
    unsigned char* buf = malloc(size);
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, base, buf, size, &bytesRead)) {
        printf("[-] Failed to read process memory\n");
        free(buf);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[*] Read %lu bytes from process memory\n", (unsigned long)bytesRead);
    
    int patches_applied = 0;
    
    // PATTERN 1: The X509 verification JNE
    // Looking for: 83 FB 0B 0F 85 xx xx xx xx
    printf("\n[*] Searching for X509 verification pattern...\n");
    printf("    Pattern: 83 FB 0B 0F 85 (cmp ebx,0xb; jne)\n");
    
    for (SIZE_T i = 0; i < bytesRead - 10; i++) {
        if (buf[i] == 0x83 && buf[i+1] == 0xFB && buf[i+2] == 0x0B &&
            buf[i+3] == 0x0F && buf[i+4] == 0x85) {
            
            printf("    [!] Found pattern at offset 0x%lx (addr 0x%p)\n", 
                   (unsigned long)i, base + i);
            
            printf("    Context: ");
            for (int j = -5; j < 15; j++) {
                if (i + j >= 0 && i + j < bytesRead)
                    printf("%02X ", buf[i + j]);
            }
            printf("\n");
            
            unsigned char nops[6] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
            if (PatchMemory(hProcess, base + i + 3, nops, 6, "X509 JNE -> NOPs")) {
                patches_applied++;
            }
        }
    }
    
    if (patches_applied == 0) {
        printf("    Pattern not found! Searching for alternative...\n");
        
        // Try just looking for 0F 85 A4 01 00 00 anywhere
        printf("\n[*] Searching for JNE with offset 0x1A4...\n");
        for (SIZE_T i = 0; i < bytesRead - 6; i++) {
            if (buf[i] == 0x0F && buf[i+1] == 0x85 && 
                buf[i+2] == 0xA4 && buf[i+3] == 0x01 && 
                buf[i+4] == 0x00 && buf[i+5] == 0x00) {
                
                printf("    [!] Found JNE at offset 0x%lx (addr 0x%p)\n", 
                       (unsigned long)i, base + i);
                
                printf("    Context: ");
                for (int j = -8; j < 10; j++) {
                    if (i + j >= 0 && i + j < bytesRead)
                        printf("%02X ", buf[i + j]);
                }
                printf("\n");
                
                unsigned char nops[6] = {0x90, 0x90, 0x90, 0x90, 0x90, 0x90};
                if (PatchMemory(hProcess, base + i, nops, 6, "JNE 0x1A4 -> NOPs")) {
                    patches_applied++;
                }
            }
        }
    }
    
    free(buf);
    CloseHandle(hProcess);
    
    printf("\n===========================================\n");
    printf("Patches applied: %d\n", patches_applied);
    printf("===========================================\n");
    
    if (patches_applied > 0) {
        printf("\n[+] SUCCESS! Try connecting to the server now.\n");
    } else {
        printf("\n[-] No patches applied. The DLL may not be unpacked yet.\n");
        printf("    Wait until the game reaches the main menu, then run again.\n");
    }
    
    return 0;
}
