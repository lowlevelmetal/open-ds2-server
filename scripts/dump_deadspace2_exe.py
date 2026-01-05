#!/usr/bin/env python3
"""
Dead Space 2 Main Executable Memory Dumper
==========================================

Dumps the decrypted .text section from a running deadspace2.exe process.
Works with Wine/Proton on Linux or native Windows.

The game uses Solidshield 2.0.3.1 protection which encrypts .text at rest.
When the game runs, the QuFIo unpacker decrypts .text in-place.
This script dumps that decrypted code for analysis.

Target: deadspace2.exe
Focus: Multiplayer connection code (BlazeSDK, DirtySock)

Usage:
    python dump_deadspace2_exe.py [--pid PID] [--wait] [--output DIR]

Session 13 - January 5, 2026
Reference: REVERSE_ENGINEERING_NOTES.md
"""

import os
import sys
import struct
import argparse
import time
import math
from pathlib import Path
from collections import Counter
from datetime import datetime

# Platform detection
IS_WINDOWS = sys.platform == 'win32'
IS_LINUX = sys.platform.startswith('linux')

# ============================================================================
# Target Binary Information (from Session 12 radare2 analysis)
# ============================================================================

TARGET_EXE = "deadspace2.exe"
PE_IMAGE_BASE = 0x00400000

# XTEA decryption key (from QuFIo section header @ 0x1EDCE28)
XTEA_KEY = bytes.fromhex("0CB82F90358B34CC5D36466A1D5D5714")

# Section layout from PE analysis (Session 12)
# Note: Wine/Proton may remap to different base address!
SECTIONS = {
    '.text': {
        'rva': 0x00001000,
        'vsize': 0x016A0000,      # 23.5 MB - main game code (ENCRYPTED at rest)
        'raw_size': 0x0169F800,
        'entropy_encrypted': 8.00,
        'characteristics': 'CODE, EXEC, READ',
    },
    '.rdata': {
        'rva': 0x01AA1000,
        'vsize': 0x0018F000,      # 1.6 MB - strings, RTTI
        'raw_size': 0x0018E400,
        'entropy_encrypted': 6.17,
        'characteristics': 'DATA, READ',
    },
    '.data': {
        'rva': 0x01C30000,
        'vsize': 0x00528000,      # 5.3 MB - initialized data
        'raw_size': 0x003EC200,
        'entropy_encrypted': 4.27,
        'characteristics': 'DATA, R/W',
    },
    '.idata': {
        'rva': 0x02158000,
        'vsize': 0x00003000,
        'raw_size': 0x00002A00,
        'characteristics': 'DATA, R/W',
    },
    'QuFIo': {
        'rva': 0x0242D000,
        'vsize': 0x00F23000,      # 15.1 MB - Solidshield unpacker
        'raw_size': 0x00F23000,
        'entropy_encrypted': 8.00,
        'characteristics': 'CODE, EXEC, READ',
    },
}

# Entry point is in QuFIo section (Solidshield stub)
ENTRY_POINT_RVA = 0x0242D049

# Key strings to identify the correct process/module
IDENTIFICATION_STRINGS = [
    b'deadspace_f.pdb',
    b'CLIENT.Ph.Visceral_EA-RedwoodShores_DeadSpace2',
    b'Solidshield',
    b'BlazeSDK',
]

# Blaze-related strings to verify we have the right section
BLAZE_MARKERS = [
    b'gosredirector.online.ea.com',
    b'Blaze::GameManager',
    b'DirtySock',
]


def calculate_entropy(data):
    """Calculate Shannon entropy of data (0-8 scale)"""
    if not data or len(data) == 0:
        return 0.0
    
    freq = Counter(data)
    length = len(data)
    entropy = 0.0
    
    for count in freq.values():
        if count > 0:
            p = count / length
            entropy -= p * math.log2(p)
    
    return entropy


def is_valid_x86_code(data):
    """Check if data looks like valid x86 code (function prologues)"""
    if not data or len(data) < 16:
        return False
    
    # Common function prologue patterns
    prologues = [
        b'\x55\x8b\xec',           # push ebp; mov ebp, esp
        b'\x55\x89\xe5',           # push ebp; mov ebp, esp (alt)
        b'\x8b\xff\x55',           # mov edi, edi; push ebp (hotpatch)
        b'\x6a',                   # push imm8
        b'\x68',                   # push imm32
        b'\x53',                   # push ebx
        b'\x56',                   # push esi
        b'\x57',                   # push edi
        b'\x83\xec',               # sub esp, imm8
        b'\x81\xec',               # sub esp, imm32
        b'\x51',                   # push ecx
        b'\x52',                   # push edx
    ]
    
    # Check first few bytes
    for pattern in prologues:
        if data.startswith(pattern):
            return True
    
    # Also check for ret instructions (functions end with these)
    ret_patterns = [b'\xc3', b'\xc2', b'\xcb', b'\xca']
    
    # Sample the data for ret instructions - decrypted code has many
    ret_count = sum(data.count(p) for p in ret_patterns)
    ret_ratio = ret_count / len(data)
    
    # Typical code has ~0.5-2% ret instructions
    if 0.003 < ret_ratio < 0.03:
        return True
    
    return False


class DeadSpace2Dumper:
    """Memory dumper for deadspace2.exe"""
    
    def __init__(self, output_dir=None):
        self.pid = None
        self.exe_base = None
        self.output_dir = Path(output_dir) if output_dir else Path('dumps')
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def log(self, msg, level='info'):
        """Print timestamped log message"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        prefix = {'info': '[*]', 'success': '[+]', 'error': '[-]', 'warn': '[!]'}
        print(f"{timestamp} {prefix.get(level, '[*]')} {msg}")
        
    def find_process(self, name_pattern=None):
        """Find Dead Space 2 process"""
        if IS_LINUX:
            return self._find_process_linux(name_pattern)
        elif IS_WINDOWS:
            return self._find_process_windows(name_pattern)
        else:
            self.log(f"Unsupported platform: {sys.platform}", 'error')
            return None
            
    def _find_process_linux(self, name_pattern=None):
        """Find Wine/Proton process on Linux"""
        import subprocess
        
        patterns = [name_pattern] if name_pattern else []
        patterns.extend(['deadspace2', 'dead space', 'ds2'])
        
        try:
            result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
            
            for line in result.stdout.split('\n'):
                line_lower = line.lower()
                
                # Look for wine/proton process running the game
                if any(p.lower() in line_lower for p in patterns if p):
                    if 'wine' in line_lower or 'proton' in line_lower or '.exe' in line_lower:
                        parts = line.split()
                        if len(parts) >= 2:
                            try:
                                pid = int(parts[1])
                                self.log(f"Found process: PID {pid}", 'success')
                                self.log(f"  {line[:120]}...")
                                self.pid = pid
                                return pid
                            except ValueError:
                                continue
                                
        except Exception as e:
            self.log(f"Error finding process: {e}", 'error')
            
        return None
        
    def _find_process_windows(self, name_pattern=None):
        """Find process on Windows"""
        import subprocess
        
        try:
            result = subprocess.run(
                ['tasklist', '/FI', 'IMAGENAME eq deadspace2.exe', '/FO', 'CSV'],
                capture_output=True, text=True
            )
            
            for line in result.stdout.split('\n')[1:]:
                if line.strip():
                    parts = line.replace('"', '').split(',')
                    if len(parts) >= 2:
                        pid = int(parts[1])
                        self.log(f"Found: deadspace2.exe (PID: {pid})", 'success')
                        self.pid = pid
                        return pid
                        
        except Exception as e:
            self.log(f"Error finding process: {e}", 'error')
            
        return None
        
    def set_pid(self, pid):
        """Set PID directly"""
        if IS_LINUX:
            if os.path.exists(f'/proc/{pid}'):
                self.pid = pid
                self.log(f"Using PID: {pid}", 'success')
                return True
        elif IS_WINDOWS:
            self.pid = pid
            self.log(f"Using PID: {pid}", 'success')
            return True
        
        self.log(f"Process {pid} not found", 'error')
        return False
        
    def find_exe_base(self):
        """Find the base address of deadspace2.exe in memory"""
        if IS_LINUX:
            return self._find_exe_base_linux()
        elif IS_WINDOWS:
            return self._find_exe_base_windows()
        return None
        
    def _find_exe_base_linux(self):
        """Find EXE base address on Linux via /proc/pid/maps"""
        if self.pid is None:
            return None
            
        maps_path = f'/proc/{self.pid}/maps'
        candidates = []
        
        try:
            with open(maps_path, 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 6:
                        addr_range = parts[0]
                        perms = parts[1]
                        path = parts[-1] if len(parts) > 5 else ''
                        
                        base = int(addr_range.split('-')[0], 16)
                        
                        # Look for deadspace2.exe mapping
                        if 'deadspace2' in path.lower():
                            candidates.append((base, path, perms))
                            
                        # Also check for mappings at expected ImageBase
                        if base == PE_IMAGE_BASE:
                            candidates.append((base, '[expected imagebase]', perms))
                            
            # Log all candidates
            self.log(f"Found {len(candidates)} potential EXE mappings:")
            for base, path, perms in candidates:
                self.log(f"  0x{base:08X} [{perms}] {path}")
                
            # Find the actual base by looking for PE header
            for base, path, perms in candidates:
                if 'r' in perms:
                    try:
                        data = self.read_memory(base, 0x1000)
                        if data and data[:2] == b'MZ':
                            # Verify it's deadspace2.exe by checking for markers
                            if self._verify_exe_identity(base):
                                self.exe_base = base
                                self.log(f"Confirmed EXE base: 0x{base:08X}", 'success')
                                return base
                    except:
                        continue
                        
            # Fallback: search all readable mappings for MZ header
            self.log("Searching memory for PE header...", 'warn')
            return self._search_for_exe_linux()
            
        except Exception as e:
            self.log(f"Error reading maps: {e}", 'error')
            
        return None
        
    def _search_for_exe_linux(self):
        """Search all memory regions for the EXE"""
        maps_path = f'/proc/{self.pid}/maps'
        
        try:
            with open(maps_path, 'r') as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 2:
                        addr_range = parts[0]
                        perms = parts[1]
                        
                        if 'r' in perms:
                            start, end = addr_range.split('-')
                            base = int(start, 16)
                            size = int(end, 16) - base
                            
                            # Skip very large regions (likely heap/stack)
                            if size > 0x10000000:  # 256MB
                                continue
                                
                            try:
                                data = self.read_memory(base, min(0x2000, size))
                                if data and data[:2] == b'MZ':
                                    # Check for our markers
                                    if any(marker in data for marker in IDENTIFICATION_STRINGS):
                                        self.exe_base = base
                                        self.log(f"Found EXE at 0x{base:08X}", 'success')
                                        return base
                            except:
                                continue
                                
        except Exception as e:
            self.log(f"Error searching memory: {e}", 'error')
            
        return None
        
    def _find_exe_base_windows(self):
        """Find EXE base address on Windows"""
        import ctypes
        from ctypes import wintypes
        
        # This would use EnumProcessModules or similar
        # For now, assume standard ImageBase
        self.exe_base = PE_IMAGE_BASE
        self.log(f"Using standard ImageBase: 0x{PE_IMAGE_BASE:08X}", 'warn')
        return PE_IMAGE_BASE
        
    def _verify_exe_identity(self, base):
        """Verify this is deadspace2.exe by checking for known strings"""
        try:
            # Read PE header and some .rdata
            data = self.read_memory(base, 0x10000)
            
            # Check for identification strings
            for marker in IDENTIFICATION_STRINGS[:2]:  # PDB and client ID
                if marker in data:
                    return True
                    
            return False
        except:
            return False
            
    def read_memory(self, address, size):
        """Read memory from process"""
        if IS_LINUX:
            return self._read_memory_linux(address, size)
        elif IS_WINDOWS:
            return self._read_memory_windows(address, size)
        return None
        
    def _read_memory_linux(self, address, size):
        """Read via /proc/pid/mem"""
        if self.pid is None:
            raise ValueError("PID not set")
            
        mem_path = f'/proc/{self.pid}/mem'
        
        try:
            with open(mem_path, 'rb') as f:
                f.seek(address)
                return f.read(size)
        except PermissionError:
            raise PermissionError(f"Cannot read memory - try running as root or use ptrace")
        except Exception as e:
            raise IOError(f"Failed to read 0x{address:08X}: {e}")
            
    def _read_memory_windows(self, address, size):
        """Read via ReadProcessMemory"""
        import ctypes
        
        kernel32 = ctypes.windll.kernel32
        
        # Open process if needed
        PROCESS_VM_READ = 0x0010
        handle = kernel32.OpenProcess(PROCESS_VM_READ, False, self.pid)
        
        if not handle:
            raise PermissionError("Cannot open process")
            
        try:
            buffer = ctypes.create_string_buffer(size)
            bytes_read = ctypes.c_size_t()
            
            if kernel32.ReadProcessMemory(handle, address, buffer, size, ctypes.byref(bytes_read)):
                return buffer.raw[:bytes_read.value]
            else:
                raise IOError(f"ReadProcessMemory failed at 0x{address:08X}")
        finally:
            kernel32.CloseHandle(handle)
            
    def check_text_decryption(self):
        """Check if .text section is decrypted"""
        if self.exe_base is None:
            self.log("EXE base not found", 'error')
            return False
            
        text_addr = self.exe_base + SECTIONS['.text']['rva']
        
        try:
            # Read first 4KB of .text
            data = self.read_memory(text_addr, 4096)
            
            if not data:
                self.log("Failed to read .text section", 'error')
                return False
                
            entropy = calculate_entropy(data)
            is_code = is_valid_x86_code(data)
            
            self.log(f".text @ 0x{text_addr:08X}")
            self.log(f"  Entropy: {entropy:.2f} (encrypted ~8.0, decrypted ~6.0)")
            self.log(f"  Looks like code: {is_code}")
            self.log(f"  First bytes: {data[:32].hex()}")
            
            # Decrypted code typically has entropy < 7.0
            if entropy < 7.0 and is_code:
                self.log(".text appears DECRYPTED!", 'success')
                return True
            elif entropy >= 7.9:
                self.log(".text still ENCRYPTED", 'warn')
                return False
            else:
                self.log(".text status uncertain", 'warn')
                return entropy < 7.5
                
        except Exception as e:
            self.log(f"Error checking .text: {e}", 'error')
            return False
            
    def wait_for_decryption(self, timeout=120, interval=2.0):
        """Wait for .text to be decrypted (game needs to reach main menu)"""
        self.log(f"Waiting for decryption (timeout: {timeout}s)")
        self.log("Make sure the game reaches the main menu!")
        
        start = time.time()
        
        while time.time() - start < timeout:
            if self.check_text_decryption():
                elapsed = time.time() - start
                self.log(f"Decryption confirmed after {elapsed:.1f}s", 'success')
                return True
                
            remaining = timeout - (time.time() - start)
            self.log(f"Still encrypted... ({remaining:.0f}s remaining)")
            time.sleep(interval)
            
        self.log("Timeout - .text still encrypted", 'error')
        return False
        
    def dump_section(self, section_name, verify=True):
        """Dump a section from memory"""
        if self.exe_base is None:
            self.log("EXE base not found", 'error')
            return None
            
        section = SECTIONS.get(section_name)
        if not section:
            self.log(f"Unknown section: {section_name}", 'error')
            return None
            
        addr = self.exe_base + section['rva']
        size = section['vsize']
        
        self.log(f"Dumping {section_name}: 0x{addr:08X} ({size:,} bytes / {size/1024/1024:.1f} MB)")
        
        try:
            # Read in chunks for large sections
            chunk_size = 0x100000  # 1MB chunks
            data = b''
            
            for offset in range(0, size, chunk_size):
                remaining = min(chunk_size, size - offset)
                chunk = self.read_memory(addr + offset, remaining)
                
                if chunk:
                    data += chunk
                    progress = (offset + remaining) / size * 100
                    if offset % (chunk_size * 4) == 0:  # Log every 4MB
                        self.log(f"  Progress: {progress:.1f}%")
                else:
                    self.log(f"  Failed at offset 0x{offset:X}", 'error')
                    break
                    
            if len(data) != size:
                self.log(f"  Warning: got {len(data)} bytes, expected {size}", 'warn')
                
            # Calculate entropy
            sample_entropy = calculate_entropy(data[:min(len(data), 0x10000)])
            self.log(f"  Entropy (first 64KB): {sample_entropy:.2f}")
            
            # Save to file
            output_path = self.output_dir / f"{section_name.replace('.', '')}_section.bin"
            with open(output_path, 'wb') as f:
                f.write(data)
            self.log(f"  Saved to: {output_path}", 'success')
            
            return data
            
        except Exception as e:
            self.log(f"Error dumping {section_name}: {e}", 'error')
            return None
            
    def dump_all_sections(self):
        """Dump all important sections"""
        results = {}
        
        # Priority: .text (code), .rdata (strings), .data (game data)
        for section_name in ['.text', '.rdata', '.data']:
            data = self.dump_section(section_name)
            if data:
                results[section_name] = data
                
        return results
        
    def verify_blaze_presence(self, text_data):
        """Verify we captured Blaze/multiplayer code"""
        if not text_data:
            return False
            
        self.log("Verifying Blaze SDK presence...")
        
        found = []
        for marker in BLAZE_MARKERS:
            if marker in text_data:
                found.append(marker.decode('utf-8', errors='ignore'))
                
        if found:
            self.log(f"Found Blaze markers: {found}", 'success')
            return True
        else:
            self.log("No Blaze markers found in .text", 'warn')
            # Blaze strings are in .rdata, not .text - this is expected
            return True  # Still valid
            
    def create_reconstructed_exe(self, sections_data):
        """Create a reconstructed EXE with decrypted sections"""
        if self.exe_base is None:
            return None
            
        self.log("Reconstructing EXE with decrypted sections...")
        
        try:
            # Read original PE headers
            headers = self.read_memory(self.exe_base, 0x1000)
            
            if not headers or headers[:2] != b'MZ':
                self.log("Invalid PE headers", 'error')
                return None
                
            # Get PE offset
            pe_offset = struct.unpack('<I', headers[0x3C:0x40])[0]
            
            # For now, just save headers + sections concatenated
            output_path = self.output_dir / "deadspace2_dumped.exe"
            
            with open(output_path, 'wb') as f:
                # Write headers
                f.write(headers)
                
                # This is a simplified reconstruction - a full one would
                # need to fix section headers, relocations, etc.
                # For analysis purposes, the individual section dumps are sufficient
                
            self.log(f"Note: Full EXE reconstruction requires PE rebuilding", 'warn')
            self.log(f"Use individual section dumps for analysis", 'info')
            
            return output_path
            
        except Exception as e:
            self.log(f"Error reconstructing EXE: {e}", 'error')
            return None
            
    def generate_analysis_script(self):
        """Generate a radare2 analysis script for the dumped .text"""
        script_content = '''#!/bin/bash
# Radare2 analysis script for dumped Dead Space 2 .text section
# Generated by dump_deadspace2_exe.py

TEXT_DUMP="dumps/text_section.bin"

if [ ! -f "$TEXT_DUMP" ]; then
    echo "Error: $TEXT_DUMP not found"
    exit 1
fi

echo "=== Dead Space 2 .text Section Analysis ==="
echo "Loading $TEXT_DUMP..."

# Open in radare2 with 32-bit x86 mode
r2 -a x86 -b 32 -m 0x00401000 "$TEXT_DUMP" << 'EOF'
# Analyze all functions
echo "Analyzing functions (this may take a while for 23MB)..."
aaa

# Find Blaze-related functions by searching for string references
echo "Searching for Blaze references..."
/ Blaze::
/ gosredirector
/ DirtySock

# List functions
echo "Function count:"
aflc

# Save analysis
echo "Saving analysis..."
Ps dumps/deadspace2_analysis.r2

echo "Done! Reopen with: r2 -p dumps/deadspace2_analysis.r2"
EOF
'''
        
        script_path = self.output_dir / "analyze_text.sh"
        with open(script_path, 'w') as f:
            f.write(script_content)
        os.chmod(script_path, 0o755)
        
        self.log(f"Generated analysis script: {script_path}", 'success')
        return script_path


def main():
    parser = argparse.ArgumentParser(
        description='Dump decrypted Dead Space 2 memory for multiplayer analysis',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
    # Auto-find game and dump after it reaches main menu
    python dump_deadspace2_exe.py --wait
    
    # Use specific PID
    python dump_deadspace2_exe.py --pid 12345
    
    # Just check status
    python dump_deadspace2_exe.py --pid 12345 --check-only
    
Notes:
    - Game must be running and past the loading screen
    - On Linux, may need root or ptrace capability
    - Dump takes ~30 seconds for 23MB .text section
'''
    )
    
    parser.add_argument('--pid', type=int, help='Process ID (auto-detect if not specified)')
    parser.add_argument('--wait', action='store_true', help='Wait for decryption to complete')
    parser.add_argument('--timeout', type=int, default=120, help='Wait timeout in seconds')
    parser.add_argument('--output', '-o', default='dumps', help='Output directory')
    parser.add_argument('--check-only', action='store_true', help='Only check decryption status')
    parser.add_argument('--section', help='Dump specific section only (e.g., .text)')
    
    args = parser.parse_args()
    
    print("=" * 60)
    print("Dead Space 2 Memory Dumper - Session 13")
    print("Target: Multiplayer/BlazeSDK code in .text section")
    print("=" * 60)
    print()
    
    dumper = DeadSpace2Dumper(output_dir=args.output)
    
    # Find or set PID
    if args.pid:
        if not dumper.set_pid(args.pid):
            sys.exit(1)
    else:
        if not dumper.find_process():
            print("\nCould not find Dead Space 2 process.")
            print("Make sure the game is running, then try:")
            print("  - Wait for the game to fully load")
            print("  - Specify PID manually: --pid <PID>")
            print("  - On Linux: ps aux | grep -i deadspace")
            sys.exit(1)
            
    # Find EXE base address
    if not dumper.find_exe_base():
        print("\nCould not find EXE in process memory.")
        print("The game may still be loading or Wine mapping is unusual.")
        sys.exit(1)
        
    # Check or wait for decryption
    if args.wait:
        if not dumper.wait_for_decryption(timeout=args.timeout):
            print("\n.text section is still encrypted.")
            print("Make sure the game reaches the main menu.")
            sys.exit(1)
    else:
        if not dumper.check_text_decryption():
            print("\n.text section appears encrypted.")
            print("Try: --wait to wait for game to decrypt")
            if args.check_only:
                sys.exit(1)
                
    if args.check_only:
        print("\nDecryption check complete.")
        sys.exit(0)
        
    # Dump sections
    print()
    if args.section:
        data = dumper.dump_section(args.section)
        if not data:
            sys.exit(1)
    else:
        sections = dumper.dump_all_sections()
        if not sections:
            sys.exit(1)
            
        # Verify we got Blaze code
        if '.text' in sections:
            dumper.verify_blaze_presence(sections['.text'])
            
    # Generate helper scripts
    dumper.generate_analysis_script()
    
    print()
    print("=" * 60)
    print("DUMP COMPLETE")
    print("=" * 60)
    print(f"Output directory: {dumper.output_dir}")
    print()
    print("Next steps:")
    print("  1. Load text_section.bin in IDA/Ghidra at base 0x00401000")
    print("  2. Run: ./dumps/analyze_text.sh for radare2 analysis")
    print("  3. Search for 'Blaze::' and 'gosredirector' strings")
    print("  4. Focus on GameManager and Authentication classes")
    print()
    

if __name__ == '__main__':
    main()
