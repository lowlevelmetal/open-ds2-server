#!/usr/bin/env python3
"""
Cross-Platform Memory Dumper for activation.x86.dll (Solidshield DRM)
Works on:
  - Linux (with Wine/Proton processes)
  - Windows (native)

Usage:
  python memory_dumper.py [--pid PID] [--process NAME] [--output DIR]

The script will:
  1. Find the process running Dead Space 2
  2. Locate activation.x86.dll in memory
  3. Dump the decrypted .text and .reloc sections
  4. Save as unpacked DLL
"""

import os
import sys
import struct
import argparse
import time
from pathlib import Path

# Platform detection
IS_WINDOWS = sys.platform == 'win32'
IS_LINUX = sys.platform.startswith('linux')

# Target DLL info
TARGET_DLL = "activation.x86.dll"
TARGET_DLL_ALT = "drmlib.dll"  # Internal name
IMAGE_BASE = 0x10000000

# Section info from PE analysis
SECTIONS = {
    '.text':  {'rva': 0x1000,   'vsize': 0x70000, 'raw_size': 0x6FC00},
    '.rdata': {'rva': 0x71000,  'vsize': 0x27000, 'raw_size': 0x26400},
    '.data':  {'rva': 0x98000,  'vsize': 0x7000,  'raw_size': 0x2400},
    '.reloc': {'rva': 0x9F000,  'vsize': 0x9000,  'raw_size': 0x8C00},
}

# Entry point (in S3 - the unpacker)
ENTRY_POINT_RVA = 0x109049

class MemoryDumperBase:
    """Base class for memory operations"""
    
    def __init__(self):
        self.pid = None
        self.dll_base = None
        
    def find_process(self, name_pattern):
        """Find process by name pattern"""
        raise NotImplementedError
        
    def get_modules(self):
        """Get list of loaded modules"""
        raise NotImplementedError
        
    def read_memory(self, address, size):
        """Read memory from process"""
        raise NotImplementedError
        
    def find_dll_base(self):
        """Find the base address of activation.x86.dll"""
        modules = self.get_modules()
        for name, base in modules:
            name_lower = name.lower()
            if TARGET_DLL.lower() in name_lower or TARGET_DLL_ALT.lower() in name_lower:
                self.dll_base = base
                print(f"[+] Found {name} at 0x{base:08X}")
                return base
        return None
        
    def dump_section(self, section_name):
        """Dump a section from memory"""
        if self.dll_base is None:
            raise ValueError("DLL base not set")
            
        section = SECTIONS.get(section_name)
        if not section:
            raise ValueError(f"Unknown section: {section_name}")
            
        address = self.dll_base + section['rva']
        size = section['vsize']
        
        print(f"[*] Dumping {section_name} from 0x{address:08X} ({size} bytes)")
        
        try:
            data = self.read_memory(address, size)
            return data
        except Exception as e:
            print(f"[-] Failed to read {section_name}: {e}")
            return None
            
    def check_decryption_status(self):
        """Check if .text section appears decrypted"""
        if self.dll_base is None:
            return False
            
        # Read first 64 bytes of .text
        address = self.dll_base + SECTIONS['.text']['rva']
        try:
            data = self.read_memory(address, 64)
            if not data:
                return False
                
            # Check for common x86 function prologue patterns
            # push ebp; mov ebp, esp = 55 8B EC
            # push ebx/esi/edi = 53/56/57
            # sub esp, XX = 83 EC XX or 81 EC XX XX XX XX
            
            valid_starts = [
                b'\x55\x8b\xec',  # push ebp; mov ebp, esp
                b'\x55\x89\xe5',  # push ebp; mov ebp, esp (alternate)
                b'\x53',          # push ebx
                b'\x56',          # push esi
                b'\x57',          # push edi
                b'\x83\xec',      # sub esp, imm8
                b'\x81\xec',      # sub esp, imm32
                b'\x8b\xff',      # mov edi, edi (hotpatch)
            ]
            
            for pattern in valid_starts:
                if data.startswith(pattern):
                    print(f"[+] .text appears DECRYPTED (starts with {pattern.hex()})")
                    return True
                    
            # Check entropy - decrypted code should have lower entropy
            entropy = self._calculate_entropy(data)
            print(f"[*] .text entropy: {entropy:.2f} (< 7.0 suggests decrypted)")
            
            if entropy < 7.0:
                return True
                
            return False
            
        except Exception as e:
            print(f"[-] Failed to check decryption: {e}")
            return False
            
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        import math
        from collections import Counter
        
        if not data:
            return 0
            
        freq = Counter(data)
        length = len(data)
        entropy = 0
        
        for count in freq.values():
            p = count / length
            entropy -= p * math.log2(p)
            
        return entropy
        
    def wait_for_decryption(self, timeout=60, poll_interval=0.5):
        """Wait until .text section is decrypted"""
        print(f"[*] Waiting for .text decryption (timeout: {timeout}s)")
        
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self.check_decryption_status():
                return True
            time.sleep(poll_interval)
            
        print("[-] Timeout waiting for decryption")
        return False


if IS_LINUX:
    class LinuxMemoryDumper(MemoryDumperBase):
        """Memory dumper for Linux (Wine/Proton processes)"""
        
        def find_process(self, name_pattern):
            """Find Wine/Proton process by name"""
            import subprocess
            
            # Look for wine/proton processes
            patterns = [name_pattern, 'deadspace2', 'dead space', 'ds2']
            
            try:
                # Get all processes
                result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
                
                for line in result.stdout.split('\n'):
                    line_lower = line.lower()
                    
                    # Check for wine/proton process with our target
                    if any(p in line_lower for p in patterns):
                        if 'wine' in line_lower or 'proton' in line_lower or '.exe' in line_lower:
                            parts = line.split()
                            if len(parts) >= 2:
                                pid = int(parts[1])
                                print(f"[+] Found process: PID {pid}")
                                print(f"    {line[:100]}...")
                                self.pid = pid
                                return pid
                                
            except Exception as e:
                print(f"[-] Error finding process: {e}")
                
            return None
            
        def find_process_by_pid(self, pid):
            """Set PID directly"""
            # Verify process exists
            if os.path.exists(f'/proc/{pid}'):
                self.pid = pid
                return pid
            return None
            
        def get_modules(self):
            """Get loaded modules from /proc/pid/maps"""
            if self.pid is None:
                return []
                
            modules = []
            maps_path = f'/proc/{self.pid}/maps'
            
            try:
                with open(maps_path, 'r') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 6:
                            addr_range = parts[0]
                            perms = parts[1]
                            path = parts[-1]
                            
                            # Get base address
                            base = int(addr_range.split('-')[0], 16)
                            
                            # Only interested in executable mappings with paths
                            if 'x' in perms and '/' in path:
                                # Check if this is our DLL
                                if any(target in path.lower() for target in [TARGET_DLL.lower(), TARGET_DLL_ALT.lower(), 'activation', 'drmlib']):
                                    modules.append((path, base))
                                    
                            # Also look for anonymous mappings at expected base
                            if base == IMAGE_BASE or (IMAGE_BASE <= base < IMAGE_BASE + 0x1000000):
                                if 'r' in perms:  # Readable
                                    modules.append((f"[anon@0x{base:08x}]", base))
                                    
            except Exception as e:
                print(f"[-] Error reading maps: {e}")
                
            return modules
            
        def read_memory(self, address, size):
            """Read memory via /proc/pid/mem"""
            if self.pid is None:
                raise ValueError("PID not set")
                
            mem_path = f'/proc/{self.pid}/mem'
            
            try:
                with open(mem_path, 'rb') as f:
                    f.seek(address)
                    data = f.read(size)
                    return data
            except Exception as e:
                raise IOError(f"Failed to read memory at 0x{address:08X}: {e}")
                
        def find_dll_base(self):
            """Find DLL base, considering Wine memory layout"""
            # First try parent method
            base = super().find_dll_base()
            if base:
                return base
                
            # Wine may map the DLL at a different address
            # Search for PE header signature
            print("[*] Searching for PE header in memory...")
            
            maps_path = f'/proc/{self.pid}/maps'
            try:
                with open(maps_path, 'r') as f:
                    for line in f:
                        parts = line.split()
                        if len(parts) >= 2:
                            addr_range = parts[0]
                            perms = parts[1]
                            
                            if 'r' in perms:
                                start = int(addr_range.split('-')[0], 16)
                                
                                # Check for MZ header
                                try:
                                    data = self.read_memory(start, 0x1000)
                                    if data and data[:2] == b'MZ':
                                        # Found PE, check if it's our DLL
                                        # Look for export name
                                        if b'drmlib.dll' in data or b'activation' in data.lower():
                                            print(f"[+] Found DLL at 0x{start:08X}")
                                            self.dll_base = start
                                            return start
                                except:
                                    continue
                                    
            except Exception as e:
                print(f"[-] Error searching for DLL: {e}")
                
            return None
            
    MemoryDumper = LinuxMemoryDumper
    

if IS_WINDOWS:
    import ctypes
    from ctypes import wintypes
    
    # Windows API constants
    PROCESS_VM_READ = 0x0010
    PROCESS_QUERY_INFORMATION = 0x0400
    
    class LinuxMemoryDumper(MemoryDumperBase):
        """Stub for Windows - not used"""
        pass
        
    class WindowsMemoryDumper(MemoryDumperBase):
        """Memory dumper for Windows"""
        
        def __init__(self):
            super().__init__()
            self.process_handle = None
            
            # Load Windows DLLs
            self.kernel32 = ctypes.windll.kernel32
            self.psapi = ctypes.windll.psapi
            
        def find_process(self, name_pattern):
            """Find process by name on Windows"""
            import subprocess
            
            try:
                # Use tasklist to find process
                result = subprocess.run(
                    ['tasklist', '/FI', f'IMAGENAME eq {name_pattern}*', '/FO', 'CSV'],
                    capture_output=True, text=True
                )
                
                for line in result.stdout.split('\n')[1:]:  # Skip header
                    if line.strip():
                        parts = line.replace('"', '').split(',')
                        if len(parts) >= 2:
                            name = parts[0]
                            pid = int(parts[1])
                            print(f"[+] Found: {name} (PID: {pid})")
                            self.pid = pid
                            return pid
                            
                # Also try deadspace2.exe
                result = subprocess.run(
                    ['tasklist', '/FI', 'IMAGENAME eq deadspace2.exe', '/FO', 'CSV'],
                    capture_output=True, text=True
                )
                
                for line in result.stdout.split('\n')[1:]:
                    if line.strip():
                        parts = line.replace('"', '').split(',')
                        if len(parts) >= 2:
                            pid = int(parts[1])
                            print(f"[+] Found: deadspace2.exe (PID: {pid})")
                            self.pid = pid
                            return pid
                            
            except Exception as e:
                print(f"[-] Error finding process: {e}")
                
            return None
            
        def find_process_by_pid(self, pid):
            """Set PID and open process handle"""
            self.pid = pid
            
            # Open process
            self.process_handle = self.kernel32.OpenProcess(
                PROCESS_VM_READ | PROCESS_QUERY_INFORMATION,
                False,
                pid
            )
            
            if not self.process_handle:
                print(f"[-] Failed to open process {pid}")
                return None
                
            return pid
            
        def get_modules(self):
            """Get loaded modules using EnumProcessModulesEx"""
            if self.process_handle is None:
                if self.pid:
                    self.find_process_by_pid(self.pid)
                else:
                    return []
                    
            modules = []
            
            # Allocate array for module handles
            hMods = (ctypes.c_void_p * 1024)()
            cbNeeded = wintypes.DWORD()
            
            # LIST_MODULES_ALL = 0x03
            if self.psapi.EnumProcessModulesEx(
                self.process_handle,
                ctypes.byref(hMods),
                ctypes.sizeof(hMods),
                ctypes.byref(cbNeeded),
                0x03
            ):
                count = cbNeeded.value // ctypes.sizeof(ctypes.c_void_p)
                
                for i in range(count):
                    hMod = hMods[i]
                    
                    # Get module name
                    modName = ctypes.create_string_buffer(260)
                    self.psapi.GetModuleFileNameExA(
                        self.process_handle,
                        hMod,
                        modName,
                        260
                    )
                    
                    # Get module base address
                    class MODULEINFO(ctypes.Structure):
                        _fields_ = [
                            ("lpBaseOfDll", ctypes.c_void_p),
                            ("SizeOfImage", wintypes.DWORD),
                            ("EntryPoint", ctypes.c_void_p),
                        ]
                        
                    modInfo = MODULEINFO()
                    self.psapi.GetModuleInformation(
                        self.process_handle,
                        hMod,
                        ctypes.byref(modInfo),
                        ctypes.sizeof(modInfo)
                    )
                    
                    name = modName.value.decode('utf-8', errors='ignore')
                    base = modInfo.lpBaseOfDll or hMod
                    
                    modules.append((name, base))
                    
            return modules
            
        def read_memory(self, address, size):
            """Read memory using ReadProcessMemory"""
            if self.process_handle is None:
                if self.pid:
                    self.find_process_by_pid(self.pid)
                else:
                    raise ValueError("No process handle")
                    
            buffer = ctypes.create_string_buffer(size)
            bytesRead = ctypes.c_size_t()
            
            result = self.kernel32.ReadProcessMemory(
                self.process_handle,
                ctypes.c_void_p(address),
                buffer,
                size,
                ctypes.byref(bytesRead)
            )
            
            if not result:
                error = ctypes.get_last_error()
                raise IOError(f"ReadProcessMemory failed at 0x{address:08X}: error {error}")
                
            return buffer.raw[:bytesRead.value]
            
        def __del__(self):
            """Clean up process handle"""
            if self.process_handle:
                self.kernel32.CloseHandle(self.process_handle)
                
    MemoryDumper = WindowsMemoryDumper


def dump_full_dll(dumper, output_dir):
    """Dump all sections and reconstruct DLL"""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Read original DLL for template
    original_dll_path = Path(__file__).parent.parent / 'bin' / 'activation.x86.dll'
    
    if not original_dll_path.exists():
        print(f"[-] Original DLL not found at {original_dll_path}")
        print("[*] Dumping sections only...")
        
        # Dump individual sections
        for section_name in SECTIONS:
            data = dumper.dump_section(section_name)
            if data:
                out_path = output_dir / f"{section_name.replace('.', '_')}_dumped.bin"
                with open(out_path, 'wb') as f:
                    f.write(data)
                print(f"[+] Saved {out_path}")
                
        return
        
    # Read original DLL
    with open(original_dll_path, 'rb') as f:
        original = bytearray(f.read())
        
    print(f"[*] Using {original_dll_path} as template")
    
    # Dump and replace encrypted sections
    sections_to_dump = ['.text', '.reloc']
    
    for section_name in sections_to_dump:
        data = dumper.dump_section(section_name)
        if data:
            section = SECTIONS[section_name]
            
            # Calculate file offset from RVA
            # For this DLL: file_offset ≈ rva - 0xC00 (approximate)
            # More accurate: use section headers
            
            # Section raw offsets from PE analysis:
            raw_offsets = {
                '.text':  0x400,
                '.rdata': 0x70400,
                '.data':  0x96800,
                '.reloc': 0x98C00,
            }
            
            raw_offset = raw_offsets.get(section_name, 0)
            raw_size = section['raw_size']
            
            print(f"[*] Patching {section_name} at file offset 0x{raw_offset:X}")
            
            # Copy dumped data (truncate to raw size)
            patch_data = data[:raw_size]
            original[raw_offset:raw_offset + len(patch_data)] = patch_data
            
            # Save individual section too
            section_path = output_dir / f"{section_name.replace('.', '_')}_decrypted.bin"
            with open(section_path, 'wb') as f:
                f.write(data)
            print(f"[+] Saved {section_path}")
            
    # Save reconstructed DLL
    out_dll_path = output_dir / 'activation.x86.unpacked.dll'
    with open(out_dll_path, 'wb') as f:
        f.write(original)
    print(f"[+] Saved reconstructed DLL: {out_dll_path}")
    
    return out_dll_path


def main():
    parser = argparse.ArgumentParser(
        description='Memory dumper for activation.x86.dll (Solidshield DRM)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Auto-find process and dump
  python memory_dumper.py
  
  # Specify PID directly
  python memory_dumper.py --pid 12345
  
  # Wait for decryption then dump
  python memory_dumper.py --wait
  
  # Custom output directory
  python memory_dumper.py --output ./dumps
  
Notes:
  - On Linux, run with sufficient privileges (same user or root)
  - The game must be running and past the protection check
  - Use --wait to automatically detect when decryption completes
"""
    )
    
    parser.add_argument('--pid', type=int, help='Process ID to attach to')
    parser.add_argument('--process', default='deadspace', help='Process name pattern')
    parser.add_argument('--output', default='./dumped', help='Output directory')
    parser.add_argument('--wait', action='store_true', help='Wait for decryption')
    parser.add_argument('--timeout', type=int, default=60, help='Wait timeout in seconds')
    parser.add_argument('--check-only', action='store_true', help='Only check decryption status')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Solidshield Memory Dumper")
    print(f"Platform: {'Windows' if IS_WINDOWS else 'Linux'}")
    print("=" * 60)
    
    # Create dumper
    dumper = MemoryDumper()
    
    # Find or set process
    if args.pid:
        print(f"[*] Using provided PID: {args.pid}")
        if not dumper.find_process_by_pid(args.pid):
            print(f"[-] Process {args.pid} not found")
            return 1
    else:
        print(f"[*] Searching for process matching '{args.process}'...")
        if not dumper.find_process(args.process):
            print("[-] Process not found. Make sure the game is running.")
            print("    Try: python memory_dumper.py --pid <PID>")
            return 1
            
    # Find DLL in memory
    print("[*] Searching for activation.x86.dll in memory...")
    if not dumper.find_dll_base():
        print("[-] Could not find activation.x86.dll")
        print("    The DLL may not be loaded yet, or Wine memory layout differs")
        
        # Try using expected base
        print(f"[*] Trying expected base address 0x{IMAGE_BASE:08X}...")
        dumper.dll_base = IMAGE_BASE
        
    # Check decryption status
    if args.check_only:
        dumper.check_decryption_status()
        return 0
        
    # Wait for decryption if requested
    if args.wait:
        if not dumper.wait_for_decryption(args.timeout):
            print("[-] Decryption not detected within timeout")
            print("    The game may need to progress further")
            return 1
    else:
        # Check current status
        if not dumper.check_decryption_status():
            print("[!] WARNING: .text may still be encrypted!")
            print("    Use --wait to wait for decryption, or continue anyway")
            response = input("    Continue with dump? [y/N]: ")
            if response.lower() != 'y':
                return 0
                
    # Dump sections
    print("\n[*] Dumping sections...")
    try:
        dump_full_dll(dumper, args.output)
        print("\n[+] Done!")
    except Exception as e:
        print(f"\n[-] Error during dump: {e}")
        import traceback
        traceback.print_exc()
        return 1
        
    return 0


if __name__ == '__main__':
    sys.exit(main())
