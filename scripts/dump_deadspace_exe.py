#!/usr/bin/env python3
"""
dump_deadspace_exe.py - Dump deadspace2.exe code section from live process

The game's .text section is at 0x00401000-0x01aa1000 (unpacked in memory)
This contains the BlazeSDK SSL code we need to analyze.
"""

import subprocess
import sys
import os

def get_pid():
    """Find Dead Space 2 PID with activation.dll loaded"""
    result = subprocess.run(
        ["pgrep", "-f", "deadspace2.exe"],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return None
    
    for pid in result.stdout.strip().split('\n'):
        if os.path.exists(f"/proc/{pid}/maps"):
            with open(f"/proc/{pid}/maps") as f:
                if "activation.x86.dll" in f.read():
                    return pid
    return None

def dump_memory(pid, start, end, output_file):
    """Dump memory region using GDB"""
    size = end - start
    print(f"Dumping 0x{start:08x}-0x{end:08x} ({size/(1024*1024):.1f} MB)...")
    
    cmd = f'sudo gdb -q -batch -p {pid} -ex "dump binary memory {output_file} 0x{start:x} 0x{end:x}"'
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    
    if os.path.exists(output_file):
        actual_size = os.path.getsize(output_file)
        print(f"  Dumped {actual_size} bytes to {output_file}")
        return True
    else:
        print(f"  FAILED to dump!")
        return False

def main():
    pid = get_pid()
    if not pid:
        print("Dead Space 2 not running")
        sys.exit(1)
    
    print(f"Found Dead Space 2 (PID: {pid})")
    
    os.makedirs("dumps", exist_ok=True)
    
    # Dump the .text section (executable code)
    # 0x00401000-0x01aa1000 is the main code section
    dump_memory(pid, 0x00401000, 0x01aa1000, "dumps/deadspace_text.bin")
    
    # Also dump the data section that has the CA certs
    # 0x01c30000-0x0201d000
    dump_memory(pid, 0x01c30000, 0x0201d000, "dumps/deadspace_data.bin")
    
    print("\nDumps complete!")
    print("Now searching for SSL patterns...")
    
    # Search for SSL-related patterns in the code
    if os.path.exists("dumps/deadspace_text.bin"):
        data = open("dumps/deadspace_text.bin", "rb").read()
        base = 0x00401000
        
        print(f"\nSearching {len(data)} bytes of code...")
        
        # Search for certificate-related patterns
        patterns = [
            (b"BEGIN CERTIFICATE", "PEM certificate marker"),
            (b"Equifax", "Equifax CA reference"),
            (b"OTG3", "OTG3 CA reference"),
            (b"\x55\x89\xe5", "Function prologue (push ebp; mov ebp,esp)"),
        ]
        
        # Search for error code patterns (bad certificate = 42 = 0x2a)
        print("\nSearching for bad_certificate (0x2a) error code...")
        count = 0
        for i in range(len(data) - 5):
            # mov eax, 0x2a
            if data[i] in [0xb8] and data[i+1:i+5] == b'\x2a\x00\x00\x00':
                addr = base + i
                print(f"  mov eax, 0x2a at 0x{addr:08x}")
                count += 1
                if count > 20:
                    print("  ... (truncated)")
                    break
        
        print(f"\nFound {count}+ potential error code locations")

if __name__ == "__main__":
    main()
