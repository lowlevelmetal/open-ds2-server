#!/usr/bin/env python3
"""
Dead Space 2 Binary Patcher

Applies specific patches to game binaries based on known offsets.
Use ssl_pattern_finder.py first to discover patch locations.

Usage:
    python apply_patch.py <dll_path> [--patch <patch_file>] [--offset <hex_offset> --value <hex_byte>]
"""

import sys
import os
import shutil
import hashlib
import json
from typing import Dict, List, Optional

# Known patch sets for different versions of the game
# Format: { "md5_hash": { "name": "version", "patches": [...] } }
KNOWN_PATCHES = {
    # These will be populated as we discover working patches
    # Example:
    # "abcd1234...": {
    #     "name": "Steam version",
    #     "patches": [
    #         {"offset": 0x12345, "original": "01", "patched": "00", "desc": "SSL verify mode"}
    #     ]
    # }
}


def create_backup(filepath: str) -> str:
    """Create a backup of the file if it doesn't exist."""
    backup_path = filepath + ".original"
    
    if os.path.exists(backup_path):
        print(f"[*] Backup already exists: {backup_path}")
        return backup_path
    
    shutil.copy2(filepath, backup_path)
    print(f"[+] Created backup: {backup_path}")
    return backup_path


def restore_backup(filepath: str) -> bool:
    """Restore the original file from backup."""
    backup_path = filepath + ".original"
    
    if not os.path.exists(backup_path):
        print(f"[-] No backup found: {backup_path}")
        return False
    
    shutil.copy2(backup_path, filepath)
    print(f"[+] Restored from backup")
    return True


def get_file_hash(filepath: str) -> str:
    """Get MD5 hash of file."""
    with open(filepath, 'rb') as f:
        return hashlib.md5(f.read()).hexdigest()


def apply_single_patch(data: bytearray, offset: int, original: bytes, patched: bytes, verify: bool = True) -> bool:
    """Apply a single patch to the data."""
    if offset < 0 or offset >= len(data):
        print(f"[-] Offset 0x{offset:X} is out of range")
        return False
    
    if offset + len(patched) > len(data):
        print(f"[-] Patch extends beyond file end")
        return False
    
    # Verify original bytes if requested
    if verify:
        current = bytes(data[offset:offset + len(original)])
        if current != original:
            print(f"[-] Original bytes mismatch at 0x{offset:X}")
            print(f"    Expected: {original.hex()}")
            print(f"    Found: {current.hex()}")
            return False
    
    # Apply patch
    data[offset:offset + len(patched)] = patched
    return True


def load_patch_file(filepath: str) -> List[Dict]:
    """Load patches from a JSON file."""
    with open(filepath, 'r') as f:
        data = json.load(f)
    
    patches = []
    for entry in data.get('patches', []):
        patches.append({
            'offset': int(entry['offset'], 16) if isinstance(entry['offset'], str) else entry['offset'],
            'original': bytes.fromhex(entry['original']),
            'patched': bytes.fromhex(entry['patched']),
            'description': entry.get('description', 'Unknown patch')
        })
    
    return patches


def save_patch_file(filepath: str, patches: List[Dict], metadata: Dict = None):
    """Save patches to a JSON file."""
    data = {
        'metadata': metadata or {},
        'patches': []
    }
    
    for patch in patches:
        data['patches'].append({
            'offset': f"0x{patch['offset']:X}",
            'original': patch['original'].hex(),
            'patched': patch['patched'].hex(),
            'description': patch.get('description', '')
        })
    
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=2)
    
    print(f"[+] Saved patch file: {filepath}")


def patch_file(filepath: str, patches: List[Dict], verify: bool = True) -> bool:
    """Apply patches to a file."""
    # Create backup
    create_backup(filepath)
    
    # Load file
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())
    
    original_hash = hashlib.md5(data).hexdigest()
    print(f"[*] Original hash: {original_hash}")
    
    # Check for known patches
    if original_hash in KNOWN_PATCHES:
        known = KNOWN_PATCHES[original_hash]
        print(f"[+] Known version detected: {known['name']}")
        if not patches:
            patches = known['patches']
            print(f"[+] Using {len(patches)} known patches")
    
    # Apply patches
    success_count = 0
    for i, patch in enumerate(patches):
        print(f"\n[*] Applying patch {i+1}/{len(patches)}: {patch.get('description', 'Unknown')}")
        print(f"    Offset: 0x{patch['offset']:X}")
        print(f"    Original: {patch['original'].hex()}")
        print(f"    Patched: {patch['patched'].hex()}")
        
        if apply_single_patch(data, patch['offset'], patch['original'], patch['patched'], verify):
            print(f"    [OK] Patch applied successfully")
            success_count += 1
        else:
            print(f"    [FAIL] Patch failed")
    
    if success_count == 0:
        print("\n[-] No patches were applied")
        return False
    
    # Save patched file
    with open(filepath, 'wb') as f:
        f.write(data)
    
    new_hash = hashlib.md5(data).hexdigest()
    print(f"\n[+] Patched {success_count}/{len(patches)} successfully")
    print(f"[+] New hash: {new_hash}")
    
    return True


def interactive_mode(filepath: str):
    """Interactive patching mode."""
    print("\n=== Interactive Patch Mode ===")
    
    with open(filepath, 'rb') as f:
        data = bytearray(f.read())
    
    while True:
        print("\nOptions:")
        print("  1. View bytes at offset")
        print("  2. Patch byte(s)")
        print("  3. Search for pattern")
        print("  4. Save changes")
        print("  5. Discard and exit")
        print("  6. Save and exit")
        
        choice = input("\nChoice: ").strip()
        
        if choice == '1':
            offset_str = input("Offset (hex, e.g., 0x1234): ").strip()
            try:
                offset = int(offset_str, 16)
                length = int(input("Length (default 32): ").strip() or "32")
                end = min(offset + length, len(data))
                
                print(f"\nBytes at 0x{offset:X}:")
                for i in range(offset, end, 16):
                    hex_bytes = ' '.join(f'{data[j]:02X}' for j in range(i, min(i+16, end)))
                    ascii_bytes = ''.join(chr(data[j]) if 32 <= data[j] < 127 else '.' 
                                         for j in range(i, min(i+16, end)))
                    print(f"  {i:08X}: {hex_bytes:<48} {ascii_bytes}")
            except ValueError as e:
                print(f"Error: {e}")
        
        elif choice == '2':
            offset_str = input("Offset (hex): ").strip()
            new_bytes_str = input("New bytes (hex, e.g., 00 or 00 01 02): ").strip()
            try:
                offset = int(offset_str, 16)
                new_bytes = bytes.fromhex(new_bytes_str.replace(' ', ''))
                
                old_bytes = bytes(data[offset:offset + len(new_bytes)])
                data[offset:offset + len(new_bytes)] = new_bytes
                
                print(f"Patched 0x{offset:X}: {old_bytes.hex()} -> {new_bytes.hex()}")
            except ValueError as e:
                print(f"Error: {e}")
        
        elif choice == '3':
            pattern_str = input("Pattern (hex bytes): ").strip()
            try:
                pattern = bytes.fromhex(pattern_str.replace(' ', ''))
                
                positions = []
                pos = 0
                while True:
                    idx = data.find(pattern, pos)
                    if idx == -1:
                        break
                    positions.append(idx)
                    pos = idx + 1
                
                print(f"Found {len(positions)} occurrences:")
                for p in positions[:20]:
                    print(f"  0x{p:08X}")
                if len(positions) > 20:
                    print(f"  ... and {len(positions) - 20} more")
            except ValueError as e:
                print(f"Error: {e}")
        
        elif choice == '4':
            with open(filepath, 'wb') as f:
                f.write(data)
            print("Changes saved")
        
        elif choice == '5':
            print("Discarding changes")
            break
        
        elif choice == '6':
            create_backup(filepath)
            with open(filepath, 'wb') as f:
                f.write(data)
            print("Changes saved")
            break


def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║     Dead Space 2 Binary Patcher                              ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python apply_patch.py <dll_path>")
        print("  python apply_patch.py <dll_path> --patch <patch.json>")
        print("  python apply_patch.py <dll_path> --offset 0x1234 --value 00")
        print("  python apply_patch.py <dll_path> --interactive")
        print("  python apply_patch.py <dll_path> --restore")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        sys.exit(1)
    
    # Parse arguments
    if '--restore' in sys.argv:
        restore_backup(filepath)
        sys.exit(0)
    
    if '--interactive' in sys.argv:
        interactive_mode(filepath)
        sys.exit(0)
    
    patches = []
    
    if '--patch' in sys.argv:
        idx = sys.argv.index('--patch')
        if idx + 1 < len(sys.argv):
            patch_file_path = sys.argv[idx + 1]
            patches = load_patch_file(patch_file_path)
            print(f"[+] Loaded {len(patches)} patches from {patch_file_path}")
    
    if '--offset' in sys.argv and '--value' in sys.argv:
        offset_idx = sys.argv.index('--offset')
        value_idx = sys.argv.index('--value')
        
        offset = int(sys.argv[offset_idx + 1], 16)
        value = bytes.fromhex(sys.argv[value_idx + 1])
        
        # Read original value
        with open(filepath, 'rb') as f:
            f.seek(offset)
            original = f.read(len(value))
        
        patches.append({
            'offset': offset,
            'original': original,
            'patched': value,
            'description': f"Manual patch at 0x{offset:X}"
        })
    
    if patches:
        patch_file(filepath, patches)
    else:
        print("[*] No patches specified, checking for known version...")
        file_hash = get_file_hash(filepath)
        
        if file_hash in KNOWN_PATCHES:
            known = KNOWN_PATCHES[file_hash]
            print(f"[+] Found known version: {known['name']}")
            patches = [
                {
                    'offset': int(p['offset'], 16) if isinstance(p['offset'], str) else p['offset'],
                    'original': bytes.fromhex(p['original']),
                    'patched': bytes.fromhex(p['patched']),
                    'description': p.get('desc', '')
                }
                for p in known['patches']
            ]
            patch_file(filepath, patches)
        else:
            print(f"[!] Unknown version (hash: {file_hash})")
            print("[*] Run ssl_pattern_finder.py to analyze the DLL")
            print("[*] Or use --interactive mode to manually patch")


if __name__ == "__main__":
    main()
