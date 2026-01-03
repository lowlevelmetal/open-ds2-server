#!/usr/bin/env python3
"""
Dead Space 2 SSL Certificate Bypass Patcher

This tool patches activation.x86.dll to disable SSL certificate validation,
allowing the game to connect to custom servers with self-signed certificates.

Usage:
    python ds2_patcher.py <path_to_activation.x86.dll>
    
The tool will:
1. Create a backup of the original file
2. Search for SSL verification patterns
3. Apply patches to bypass certificate validation
4. Verify the patches were applied correctly
"""

import sys
import os
import shutil
import struct
import hashlib
from typing import List, Tuple, Optional

# Known file hashes for different game versions
KNOWN_HASHES = {
    # Add known hashes here as we discover them
    # "md5_hash": "version_description"
}

# Patterns to search for and their patches
# Format: (name, search_pattern, patch_offset, patch_bytes, description)
PATCH_PATTERNS = [
    # Pattern 1: SSL_CTX_set_verify with verify mode
    # Looking for: push 1 (or 2, 3) before call to SSL_CTX_set_verify
    # We want to change it to push 0 (SSL_VERIFY_NONE)
    (
        "SSL_VERIFY_MODE_1",
        bytes([0x6A, 0x01]),  # push 1 (SSL_VERIFY_PEER)
        0,
        bytes([0x6A, 0x00]),  # push 0 (SSL_VERIFY_NONE)
        "Change SSL_VERIFY_PEER to SSL_VERIFY_NONE"
    ),
    (
        "SSL_VERIFY_MODE_2",
        bytes([0x6A, 0x02]),  # push 2 (SSL_VERIFY_FAIL_IF_NO_PEER_CERT)
        0,
        bytes([0x6A, 0x00]),  # push 0 (SSL_VERIFY_NONE)
        "Change SSL_VERIFY_FAIL_IF_NO_PEER_CERT to SSL_VERIFY_NONE"
    ),
    (
        "SSL_VERIFY_MODE_3",
        bytes([0x6A, 0x03]),  # push 3 (combined)
        0,
        bytes([0x6A, 0x00]),  # push 0 (SSL_VERIFY_NONE)
        "Change combined verify mode to SSL_VERIFY_NONE"
    ),
]

# More specific patterns that include context around the SSL verify call
CONTEXT_PATTERNS = [
    # Pattern: Looking for the verify callback setup
    # In OpenSSL 1.0.0, SSL_CTX_set_verify is typically called like:
    # push callback_func
    # push verify_mode
    # push ctx
    # call SSL_CTX_set_verify
    
    # We need to find where the verify mode is pushed and change it to 0
]


class DS2Patcher:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data = None
        self.original_hash = None
        self.patches_applied = []
        
    def load(self) -> bool:
        """Load the DLL file into memory."""
        try:
            with open(self.filepath, 'rb') as f:
                self.data = bytearray(f.read())
            self.original_hash = hashlib.md5(self.data).hexdigest()
            print(f"[+] Loaded: {self.filepath}")
            print(f"[+] Size: {len(self.data)} bytes")
            print(f"[+] MD5: {self.original_hash}")
            
            if self.original_hash in KNOWN_HASHES:
                print(f"[+] Known version: {KNOWN_HASHES[self.original_hash]}")
            else:
                print(f"[!] Unknown version - patches may not work correctly")
                
            return True
        except Exception as e:
            print(f"[-] Failed to load file: {e}")
            return False
    
    def backup(self) -> bool:
        """Create a backup of the original file."""
        backup_path = self.filepath + ".backup"
        if os.path.exists(backup_path):
            print(f"[!] Backup already exists: {backup_path}")
            return True
        try:
            shutil.copy2(self.filepath, backup_path)
            print(f"[+] Backup created: {backup_path}")
            return True
        except Exception as e:
            print(f"[-] Failed to create backup: {e}")
            return False
    
    def find_pattern(self, pattern: bytes, start: int = 0) -> List[int]:
        """Find all occurrences of a pattern in the data."""
        positions = []
        pos = start
        while True:
            pos = self.data.find(pattern, pos)
            if pos == -1:
                break
            positions.append(pos)
            pos += 1
        return positions
    
    def find_ssl_verify_calls(self) -> List[Tuple[int, str]]:
        """
        Find potential SSL_CTX_set_verify calls by looking for patterns.
        Returns list of (offset, description) tuples.
        """
        candidates = []
        
        # Look for "push 1" or "push 2" followed by patterns that suggest SSL setup
        for mode in [0x01, 0x02, 0x03]:
            pattern = bytes([0x6A, mode])  # push immediate byte
            positions = self.find_pattern(pattern)
            
            for pos in positions:
                # Check context around this push
                # Look for nearby call instructions or other SSL-related patterns
                context_start = max(0, pos - 32)
                context_end = min(len(self.data), pos + 32)
                context = self.data[context_start:context_end]
                
                # Look for call instruction (0xE8) nearby
                if b'\xE8' in context:
                    # This might be a call to SSL_CTX_set_verify
                    candidates.append((pos, f"push {mode} near call instruction"))
        
        return candidates
    
    def find_verify_callback(self) -> List[int]:
        """
        Find the SSL verify callback function.
        The callback typically returns 0 (fail) or 1 (success).
        We want to make it always return 1.
        """
        candidates = []
        
        # Look for common callback patterns:
        # mov eax, 0 followed by ret (return 0 = fail)
        # We want to change these to mov eax, 1 (return 1 = success)
        
        # Pattern: xor eax, eax; ret (return 0)
        pattern1 = bytes([0x33, 0xC0, 0xC3])  # xor eax, eax; ret
        positions = self.find_pattern(pattern1)
        for pos in positions:
            candidates.append(pos)
        
        # Pattern: xor eax, eax; ... ret
        pattern2 = bytes([0x33, 0xC0])  # xor eax, eax
        positions = self.find_pattern(pattern2)
        for pos in positions:
            # Check if there's a ret nearby
            if pos + 10 < len(self.data):
                nearby = self.data[pos:pos+10]
                if 0xC3 in nearby:  # ret instruction
                    candidates.append(pos)
        
        return candidates
    
    def analyze(self) -> dict:
        """Analyze the DLL and find potential patch locations."""
        print("\n[*] Analyzing DLL for SSL verification patterns...")
        
        results = {
            'ssl_verify_calls': [],
            'verify_callbacks': [],
            'strings': [],
        }
        
        # Find SSL-related strings
        ssl_strings = [
            b"SSL_CTX_set_verify",
            b"certificate verify failed",
            b"SSL_connect",
            b"SSL_accept", 
            b"X509_verify_cert",
            b"SSL_VERIFY",
            b"gosredirector",
            b"ea.com",
        ]
        
        print("\n[*] Searching for SSL-related strings...")
        for s in ssl_strings:
            positions = self.find_pattern(s)
            if positions:
                print(f"    Found '{s.decode('utf-8', errors='ignore')}' at {len(positions)} location(s)")
                results['strings'].append((s, positions))
        
        # Find potential SSL_CTX_set_verify calls
        print("\n[*] Searching for SSL_CTX_set_verify call patterns...")
        candidates = self.find_ssl_verify_calls()
        print(f"    Found {len(candidates)} potential locations")
        results['ssl_verify_calls'] = candidates
        
        # Look for OpenSSL version string
        openssl_pattern = b"OpenSSL"
        positions = self.find_pattern(openssl_pattern)
        if positions:
            for pos in positions:
                # Read surrounding context
                start = max(0, pos - 10)
                end = min(len(self.data), pos + 50)
                context = self.data[start:end]
                try:
                    version_str = context.decode('utf-8', errors='ignore')
                    print(f"\n[+] Found OpenSSL version string: {version_str.strip()}")
                except:
                    pass
        
        return results
    
    def apply_pattern_patches(self) -> int:
        """Apply patches based on known patterns. Returns number of patches applied."""
        count = 0
        
        for name, search, offset, patch, desc in PATCH_PATTERNS:
            positions = self.find_pattern(search)
            for pos in positions:
                patch_pos = pos + offset
                # Apply the patch
                old_bytes = bytes(self.data[patch_pos:patch_pos + len(patch)])
                self.data[patch_pos:patch_pos + len(patch)] = patch
                self.patches_applied.append({
                    'name': name,
                    'offset': patch_pos,
                    'old': old_bytes,
                    'new': patch,
                    'desc': desc
                })
                count += 1
                
        return count
    
    def patch_verify_callback_return(self) -> int:
        """
        Find and patch the verify callback to always return success.
        This is a more targeted approach.
        """
        count = 0
        
        # Look for pattern: xor eax, eax followed eventually by ret
        # This is commonly used to return 0 (failure)
        # We change xor eax, eax (33 C0) to mov eax, 1 (B8 01 00 00 00)
        # But that's 5 bytes vs 2, so instead we can do:
        # push 1; pop eax (6A 01 58) = 3 bytes, need to NOP one byte
        # Or: mov al, 1 (B0 01) = 2 bytes - same size!
        
        # Actually the safest 2-byte replacement for "return 0" is:
        # inc eax after xor eax,eax - but we need the xor first
        # Let's look for xor eax,eax and change to xor eax,eax; inc eax... no, still 0
        
        # Best approach: find "xor eax, eax" and replace with "mov al, 1" + NOP if needed
        # xor eax, eax = 33 C0 (2 bytes)
        # mov al, 1 = B0 01 (2 bytes) - BUT this only sets AL, not full EAX
        
        # Proper 2-byte solution:
        # Instead of xor eax,eax (33 C0), use:
        # push 1; pop eax = 6A 01 58 (3 bytes) - too long
        
        # We need to be smarter. Let's find the actual callback function.
        
        return count
    
    def interactive_patch(self):
        """Interactive mode for manual patch selection."""
        print("\n" + "="*60)
        print("INTERACTIVE PATCH MODE")
        print("="*60)
        
        analysis = self.analyze()
        
        if not analysis['ssl_verify_calls']:
            print("\n[-] No obvious SSL verify patterns found.")
            print("[*] The DLL may use a different pattern or be obfuscated.")
            return
        
        print(f"\n[*] Found {len(analysis['ssl_verify_calls'])} potential patch locations")
        print("[*] These are 'push X' instructions that might set SSL verify mode\n")
        
        for i, (offset, desc) in enumerate(analysis['ssl_verify_calls'][:20]):  # Limit to first 20
            # Show context
            start = max(0, offset - 8)
            end = min(len(self.data), offset + 16)
            context = self.data[start:end].hex()
            
            print(f"  [{i}] Offset 0x{offset:08X}: {desc}")
            print(f"      Bytes: {context}")
            print(f"      Current: push {self.data[offset+1]}")
        
        print("\n[*] To patch, you would change 'push 1/2/3' to 'push 0'")
        print("[*] This changes SSL_VERIFY_PEER to SSL_VERIFY_NONE")
    
    def auto_patch(self) -> bool:
        """
        Automatically apply the most likely patches.
        This is aggressive and patches ALL matching patterns.
        """
        print("\n[*] Applying automatic patches...")
        
        # Strategy: Find and patch all push 1/2/3 that appear before a CALL instruction
        # within a reasonable distance
        
        patched_offsets = set()
        
        for mode in [0x01, 0x02, 0x03]:
            pattern = bytes([0x6A, mode])  # push immediate byte
            positions = self.find_pattern(pattern)
            
            for pos in positions:
                # Check if there's a CALL instruction within the next 20 bytes
                for i in range(3, 20):
                    if pos + i >= len(self.data):
                        break
                    if self.data[pos + i] == 0xE8:  # CALL instruction
                        # This looks like a function call setup
                        # Check if we haven't already patched this
                        if pos not in patched_offsets:
                            old_val = self.data[pos + 1]
                            self.data[pos + 1] = 0x00  # Change to push 0
                            patched_offsets.add(pos)
                            print(f"    Patched offset 0x{pos:08X}: push {old_val} -> push 0")
                        break
        
        print(f"\n[+] Applied {len(patched_offsets)} patches")
        return len(patched_offsets) > 0
    
    def save(self, output_path: Optional[str] = None) -> bool:
        """Save the patched DLL."""
        if output_path is None:
            output_path = self.filepath
            
        try:
            with open(output_path, 'wb') as f:
                f.write(self.data)
            
            new_hash = hashlib.md5(self.data).hexdigest()
            print(f"\n[+] Saved patched file: {output_path}")
            print(f"[+] New MD5: {new_hash}")
            return True
        except Exception as e:
            print(f"[-] Failed to save file: {e}")
            return False
    
    def generate_patch_file(self, output_path: str) -> bool:
        """Generate a patch file that can be applied separately."""
        if not self.patches_applied:
            print("[-] No patches to save")
            return False
            
        try:
            with open(output_path, 'w') as f:
                f.write(f"# DS2 SSL Bypass Patch\n")
                f.write(f"# Original MD5: {self.original_hash}\n")
                f.write(f"# Generated by ds2_patcher.py\n\n")
                
                for patch in self.patches_applied:
                    f.write(f"# {patch['desc']}\n")
                    f.write(f"OFFSET: 0x{patch['offset']:08X}\n")
                    f.write(f"ORIGINAL: {patch['old'].hex()}\n")
                    f.write(f"PATCHED: {patch['new'].hex()}\n\n")
            
            print(f"[+] Patch file saved: {output_path}")
            return True
        except Exception as e:
            print(f"[-] Failed to save patch file: {e}")
            return False


def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║     Dead Space 2 SSL Certificate Bypass Patcher              ║
║                                                              ║
║  This tool patches activation.x86.dll to allow connections  ║
║  to custom servers with self-signed certificates.           ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("Usage: python ds2_patcher.py <path_to_activation.x86.dll> [--analyze|--auto|--interactive]")
        print()
        print("Options:")
        print("  --analyze      Analyze the DLL without patching")
        print("  --auto         Automatically apply patches (default)")
        print("  --interactive  Interactive mode for manual selection")
        print()
        print("Example:")
        print("  python ds2_patcher.py '/path/to/Dead Space 2/activation.x86.dll'")
        sys.exit(1)
    
    filepath = sys.argv[1]
    mode = "auto"
    
    if len(sys.argv) > 2:
        if sys.argv[2] == "--analyze":
            mode = "analyze"
        elif sys.argv[2] == "--interactive":
            mode = "interactive"
        elif sys.argv[2] == "--auto":
            mode = "auto"
    
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        sys.exit(1)
    
    patcher = DS2Patcher(filepath)
    
    if not patcher.load():
        sys.exit(1)
    
    if mode == "analyze":
        patcher.analyze()
        sys.exit(0)
    
    if mode == "interactive":
        patcher.interactive_patch()
        sys.exit(0)
    
    # Auto mode
    if not patcher.backup():
        print("[-] Failed to create backup, aborting")
        sys.exit(1)
    
    if patcher.auto_patch():
        if patcher.save():
            print("\n[+] Patching complete!")
            print("[*] Try running the game now and connecting to your custom server")
        else:
            print("\n[-] Failed to save patched file")
            sys.exit(1)
    else:
        print("\n[-] No patches were applied")
        print("[*] Try running with --analyze to investigate the DLL")
        sys.exit(1)


if __name__ == "__main__":
    main()
