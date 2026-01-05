#!/usr/bin/env python3
"""
Helper script to find Dead Space 2 process running under Wine/Proton.
Shows all relevant processes and their memory maps.
"""

import os
import sys
import subprocess
from pathlib import Path

def find_wine_processes():
    """Find all Wine/Proton related processes"""
    
    print("=" * 70)
    print("Searching for Dead Space 2 / Wine / Proton processes")
    print("=" * 70)
    
    # Get all processes
    result = subprocess.run(['ps', 'aux'], capture_output=True, text=True)
    
    keywords = ['wine', 'proton', 'deadspace', 'dead space', 'ds2', 'steam', 'activation']
    found = []
    
    for line in result.stdout.split('\n'):
        line_lower = line.lower()
        if any(kw in line_lower for kw in keywords):
            # Parse ps aux output
            parts = line.split(None, 10)
            if len(parts) >= 11:
                user, pid, cpu, mem, vsz, rss, tty, stat, start, time_val, cmd = parts
                found.append({
                    'pid': pid,
                    'user': user,
                    'cpu': cpu,
                    'mem': mem,
                    'cmd': cmd[:80]
                })
                
    if not found:
        print("\n[-] No relevant processes found.")
        print("    Make sure Dead Space 2 is running.")
        return []
        
    print(f"\n[+] Found {len(found)} relevant processes:\n")
    
    for i, proc in enumerate(found):
        print(f"  [{i+1}] PID: {proc['pid']:>8}  CPU: {proc['cpu']:>5}%  MEM: {proc['mem']:>5}%")
        print(f"      CMD: {proc['cmd']}")
        print()
        
    return found

def check_process_maps(pid):
    """Check memory maps for a specific process"""
    
    maps_path = f'/proc/{pid}/maps'
    
    if not os.path.exists(maps_path):
        print(f"[-] Cannot access {maps_path}")
        return
        
    print(f"\n{'=' * 70}")
    print(f"Memory maps for PID {pid}")
    print(f"{'=' * 70}")
    
    try:
        with open(maps_path, 'r') as f:
            maps = f.read()
    except PermissionError:
        print(f"[-] Permission denied reading {maps_path}")
        print("    Try running as the same user that started the game")
        return
        
    # Look for relevant mappings
    interesting = []
    dll_found = False
    
    for line in maps.split('\n'):
        line_lower = line.lower()
        
        # Check for our DLL
        if 'activation' in line_lower or 'drmlib' in line_lower:
            interesting.append(('DLL', line))
            dll_found = True
            
        # Check for expected image base region
        if line.startswith('10000000') or line.startswith('10001000'):
            interesting.append(('IMAGE_BASE', line))
            
        # Check for executable sections
        parts = line.split()
        if len(parts) >= 2:
            perms = parts[1]
            if 'x' in perms and len(parts) >= 6:
                path = parts[-1]
                if '.exe' in path.lower() or '.dll' in path.lower():
                    interesting.append(('EXE/DLL', line))
                    
    if interesting:
        print("\n[+] Interesting mappings:\n")
        for tag, line in interesting:
            print(f"  [{tag:10}] {line[:100]}")
    else:
        print("\n[-] No activation.x86.dll found in memory maps")
        print("    The DLL may not be loaded yet")
        
    # Summary
    print(f"\n{'=' * 70}")
    print("Summary")
    print(f"{'=' * 70}")
    
    if dll_found:
        print(f"[+] activation.x86.dll FOUND in PID {pid}")
        print(f"    Run: python scripts/memory_dumper.py --pid {pid} --wait")
    else:
        print(f"[-] activation.x86.dll NOT found in PID {pid}")
        print("    Try a different PID from the list above")
        print("    Or wait for the game to load further")

def main():
    print("\n" + "=" * 70)
    print("Dead Space 2 Process Finder (Linux/Proton)")
    print("=" * 70 + "\n")
    
    # Find processes
    processes = find_wine_processes()
    
    if not processes:
        return 1
        
    # If only one process, check it automatically
    if len(processes) == 1:
        pid = processes[0]['pid']
        check_process_maps(pid)
    else:
        # Ask user which to check
        print("\n" + "-" * 70)
        print("Enter a PID to check its memory maps, or 'all' to check all")
        print("(or Ctrl+C to exit)")
        print("-" * 70)
        
        try:
            choice = input("\nPID or 'all': ").strip()
            
            if choice.lower() == 'all':
                for proc in processes:
                    check_process_maps(proc['pid'])
            else:
                check_process_maps(choice)
                
        except KeyboardInterrupt:
            print("\n\nExiting.")
            
    return 0

if __name__ == '__main__':
    sys.exit(main())
