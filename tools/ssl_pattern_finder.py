#!/usr/bin/env python3
"""
SSL Pattern Finder for Dead Space 2

This tool performs deep analysis of the activation.x86.dll to find
SSL certificate verification patterns that can be patched.

The game uses OpenSSL and the standard verification flow:
1. SSL_CTX_new() creates context
2. SSL_CTX_set_verify(ctx, mode, callback) sets verification
3. SSL_connect() performs handshake with verification

We need to find and neutralize step 2.
"""

import sys
import os
import struct
import re
from typing import List, Dict, Tuple, Optional
from dataclasses import dataclass


@dataclass
class PESection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_address: int
    raw_size: int
    characteristics: int


class PEAnalyzer:
    """Parse PE format to find code sections and imports."""
    
    def __init__(self, data: bytes):
        self.data = data
        self.sections: List[PESection] = []
        self.imports: Dict[str, List[str]] = {}
        self.image_base = 0
        
    def parse(self) -> bool:
        """Parse PE headers."""
        try:
            # Check MZ signature
            if self.data[:2] != b'MZ':
                print("[-] Not a valid PE file (missing MZ)")
                return False
            
            # Get PE header offset
            pe_offset = struct.unpack('<I', self.data[0x3C:0x40])[0]
            
            # Check PE signature
            if self.data[pe_offset:pe_offset+4] != b'PE\x00\x00':
                print("[-] Not a valid PE file (missing PE signature)")
                return False
            
            # Parse COFF header
            coff_offset = pe_offset + 4
            num_sections = struct.unpack('<H', self.data[coff_offset+2:coff_offset+4])[0]
            optional_header_size = struct.unpack('<H', self.data[coff_offset+16:coff_offset+18])[0]
            
            # Parse optional header
            opt_offset = coff_offset + 20
            magic = struct.unpack('<H', self.data[opt_offset:opt_offset+2])[0]
            
            if magic == 0x10b:  # PE32
                self.image_base = struct.unpack('<I', self.data[opt_offset+28:opt_offset+32])[0]
            elif magic == 0x20b:  # PE32+
                self.image_base = struct.unpack('<Q', self.data[opt_offset+24:opt_offset+32])[0]
            
            print(f"[+] Image base: 0x{self.image_base:08X}")
            print(f"[+] Number of sections: {num_sections}")
            
            # Parse sections
            section_offset = opt_offset + optional_header_size
            for i in range(num_sections):
                sec_data = self.data[section_offset + i*40:section_offset + (i+1)*40]
                name = sec_data[:8].rstrip(b'\x00').decode('utf-8', errors='ignore')
                virtual_size = struct.unpack('<I', sec_data[8:12])[0]
                virtual_address = struct.unpack('<I', sec_data[12:16])[0]
                raw_size = struct.unpack('<I', sec_data[16:20])[0]
                raw_address = struct.unpack('<I', sec_data[20:24])[0]
                characteristics = struct.unpack('<I', sec_data[36:40])[0]
                
                section = PESection(name, virtual_address, virtual_size, 
                                   raw_address, raw_size, characteristics)
                self.sections.append(section)
                
                is_code = characteristics & 0x20  # IMAGE_SCN_CNT_CODE
                is_exec = characteristics & 0x20000000  # IMAGE_SCN_MEM_EXECUTE
                print(f"    Section: {name:8s} VA: 0x{virtual_address:08X} "
                      f"Size: {virtual_size:8d} {'[CODE]' if is_code or is_exec else ''}")
            
            return True
            
        except Exception as e:
            print(f"[-] Failed to parse PE: {e}")
            return False
    
    def get_code_sections(self) -> List[PESection]:
        """Get sections that contain executable code."""
        return [s for s in self.sections 
                if (s.characteristics & 0x20) or (s.characteristics & 0x20000000)]
    
    def rva_to_offset(self, rva: int) -> Optional[int]:
        """Convert RVA to file offset."""
        for section in self.sections:
            if section.virtual_address <= rva < section.virtual_address + section.virtual_size:
                return rva - section.virtual_address + section.raw_address
        return None
    
    def offset_to_rva(self, offset: int) -> Optional[int]:
        """Convert file offset to RVA."""
        for section in self.sections:
            if section.raw_address <= offset < section.raw_address + section.raw_size:
                return offset - section.raw_address + section.virtual_address
        return None


class SSLPatternFinder:
    """Find SSL verification patterns in code."""
    
    def __init__(self, data: bytes, pe: PEAnalyzer):
        self.data = data
        self.pe = pe
        self.findings: List[Dict] = []
        
    def find_string(self, s: bytes) -> List[int]:
        """Find all occurrences of a string."""
        positions = []
        pos = 0
        while True:
            pos = self.data.find(s, pos)
            if pos == -1:
                break
            positions.append(pos)
            pos += 1
        return positions
    
    def find_ssl_strings(self) -> Dict[str, List[int]]:
        """Find SSL-related strings in the binary."""
        strings_to_find = [
            b"SSL_CTX_set_verify",
            b"SSL_set_verify",
            b"SSL_CTX_set_cert_verify_callback",
            b"X509_verify_cert",
            b"certificate verify failed",
            b"unable to get local issuer certificate",
            b"self signed certificate",
            b"certificate has expired",
            b"SSL_VERIFY_PEER",
            b"SSL_VERIFY_NONE",
            b"VERIFY_PARAM",
            b"ssl_verify",
            b"verify callback",
            b"cert_verify",
        ]
        
        results = {}
        for s in strings_to_find:
            positions = self.find_string(s)
            if positions:
                results[s.decode('utf-8', errors='ignore')] = positions
                
        return results
    
    def find_ssl_ctx_set_verify_pattern(self) -> List[Dict]:
        """
        Find the SSL_CTX_set_verify call pattern.
        
        Typical x86 calling convention:
            push callback_address  ; or 0 for NULL callback
            push verify_mode       ; 0=NONE, 1=PEER, 2=FAIL_IF_NO_CERT, 3=combined
            push/mov ctx          
            call SSL_CTX_set_verify
        
        Or for __cdecl:
            push callback
            push mode
            push ctx
            call func
            add esp, 0xC  ; cleanup
        """
        patterns = []
        
        # Get code sections
        code_sections = self.pe.get_code_sections()
        if not code_sections:
            print("[-] No code sections found")
            return patterns
        
        for section in code_sections:
            start = section.raw_address
            end = start + section.raw_size
            code = self.data[start:end]
            
            # Pattern 1: push 1/2/3 followed by push and call
            # 6A 01/02/03 = push 1/2/3
            for mode in [1, 2, 3]:
                pos = 0
                while True:
                    # Find push X where X is verify mode
                    idx = code.find(bytes([0x6A, mode]), pos)
                    if idx == -1:
                        break
                    
                    # Check surrounding context
                    ctx_start = max(0, idx - 16)
                    ctx_end = min(len(code), idx + 32)
                    context = code[ctx_start:ctx_end]
                    
                    # Look for call instruction within next 16 bytes
                    has_call = False
                    call_offset = -1
                    for i in range(2, 16):
                        if idx + i < len(code) and code[idx + i] == 0xE8:
                            has_call = True
                            call_offset = i
                            break
                    
                    if has_call:
                        file_offset = start + idx
                        rva = self.pe.offset_to_rva(file_offset)
                        
                        patterns.append({
                            'type': 'push_mode_before_call',
                            'file_offset': file_offset,
                            'rva': rva,
                            'verify_mode': mode,
                            'call_distance': call_offset,
                            'section': section.name,
                            'context': self.data[file_offset-8:file_offset+16].hex(),
                            'confidence': 'medium'
                        })
                    
                    pos = idx + 1
        
        return patterns
    
    def find_verify_callback_candidates(self) -> List[Dict]:
        """
        Find functions that could be SSL verify callbacks.
        
        SSL verify callback signature: int callback(int preverify_ok, X509_STORE_CTX *ctx)
        - Returns 0 to reject, 1 to accept
        - Often contains comparison with preverify_ok parameter
        """
        candidates = []
        
        code_sections = self.pe.get_code_sections()
        
        for section in code_sections:
            start = section.raw_address
            end = start + section.raw_size
            code = self.data[start:end]
            
            # Look for small functions that return 0 or 1
            # Pattern: function prologue ... return value ... epilogue
            
            # Pattern: xor eax, eax; ret (return 0)
            # 33 C0 C3
            pos = 0
            while True:
                idx = code.find(b'\x33\xC0\xC3', pos)
                if idx == -1:
                    break
                
                file_offset = start + idx
                rva = self.pe.offset_to_rva(file_offset)
                
                # Check if this looks like it's inside a function
                # Look for function prologue nearby (push ebp; mov ebp, esp)
                prologue_pattern = b'\x55\x8B\xEC'  # push ebp; mov ebp, esp
                search_start = max(0, idx - 64)
                prologue_idx = code.find(prologue_pattern, search_start, idx)
                
                if prologue_idx != -1:
                    func_start = start + prologue_idx
                    candidates.append({
                        'type': 'return_zero_function',
                        'file_offset': file_offset,
                        'func_start_offset': func_start,
                        'rva': rva,
                        'section': section.name,
                        'context': self.data[func_start:file_offset+8].hex(),
                        'description': 'Function that returns 0 (potential verify fail)'
                    })
                
                pos = idx + 1
            
            # Pattern: mov eax, 1; ret (return 1)
            # B8 01 00 00 00 C3
            pos = 0
            while True:
                idx = code.find(b'\xB8\x01\x00\x00\x00\xC3', pos)
                if idx == -1:
                    break
                
                file_offset = start + idx
                rva = self.pe.offset_to_rva(file_offset)
                
                candidates.append({
                    'type': 'return_one_function',
                    'file_offset': file_offset,
                    'rva': rva,
                    'section': section.name,
                    'context': self.data[file_offset:file_offset+8].hex(),
                    'description': 'Function that returns 1 (potential verify success)'
                })
                
                pos = idx + 1
        
        return candidates
    
    def find_certificate_error_strings(self) -> List[Dict]:
        """Find references to certificate error strings."""
        error_strings = [
            b"certificate verify failed",
            b"unable to verify",
            b"verify error",
            b"self signed",
            b"cert chain",
            b"issuer certificate",
        ]
        
        findings = []
        
        for s in error_strings:
            positions = self.find_string(s)
            for pos in positions:
                # Find cross-references to this string
                # Look for the address being pushed or moved
                rva = self.pe.offset_to_rva(pos)
                if rva:
                    va = self.pe.image_base + rva
                    # Search for this address in the code
                    va_bytes = struct.pack('<I', va)
                    refs = self.find_string(va_bytes)
                    
                    findings.append({
                        'string': s.decode('utf-8', errors='ignore'),
                        'file_offset': pos,
                        'rva': rva,
                        'references': refs
                    })
        
        return findings
    
    def analyze(self) -> Dict:
        """Perform full analysis."""
        print("\n" + "="*60)
        print("SSL Pattern Analysis")
        print("="*60)
        
        results = {
            'ssl_strings': {},
            'verify_patterns': [],
            'callback_candidates': [],
            'error_strings': []
        }
        
        # Find SSL strings
        print("\n[*] Searching for SSL-related strings...")
        results['ssl_strings'] = self.find_ssl_strings()
        for name, positions in results['ssl_strings'].items():
            print(f"    Found: {name} at {len(positions)} location(s)")
            for pos in positions[:3]:  # Show first 3
                print(f"        Offset: 0x{pos:08X}")
        
        # Find SSL_CTX_set_verify patterns
        print("\n[*] Searching for SSL_CTX_set_verify call patterns...")
        results['verify_patterns'] = self.find_ssl_ctx_set_verify_pattern()
        print(f"    Found {len(results['verify_patterns'])} potential patterns")
        
        # Show top candidates
        for pattern in results['verify_patterns'][:10]:
            print(f"\n    Offset: 0x{pattern['file_offset']:08X} (RVA: 0x{pattern['rva']:08X})")
            print(f"    Section: {pattern['section']}")
            print(f"    Verify mode: {pattern['verify_mode']} ({self._mode_name(pattern['verify_mode'])})")
            print(f"    Context: {pattern['context']}")
        
        # Find callback candidates
        print("\n[*] Searching for verify callback candidates...")
        results['callback_candidates'] = self.find_verify_callback_candidates()
        print(f"    Found {len(results['callback_candidates'])} potential callbacks")
        
        # Find error strings
        print("\n[*] Searching for certificate error strings...")
        results['error_strings'] = self.find_certificate_error_strings()
        for finding in results['error_strings']:
            print(f"    '{finding['string']}' at 0x{finding['file_offset']:08X}")
            if finding['references']:
                print(f"        Referenced from: {finding['references'][:3]}")
        
        return results
    
    def _mode_name(self, mode: int) -> str:
        modes = {
            0: "SSL_VERIFY_NONE",
            1: "SSL_VERIFY_PEER",
            2: "SSL_VERIFY_FAIL_IF_NO_PEER_CERT",
            3: "SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT"
        }
        return modes.get(mode, f"Unknown ({mode})")
    
    def suggest_patches(self) -> List[Dict]:
        """Suggest patches based on analysis."""
        patches = []
        
        # For each verify pattern, suggest changing the mode to 0
        for pattern in self.findings:
            if pattern.get('verify_mode', 0) > 0:
                patches.append({
                    'offset': pattern['file_offset'] + 1,  # +1 to skip the 0x6A opcode
                    'original': bytes([pattern['verify_mode']]),
                    'patched': bytes([0x00]),
                    'description': f"Change verify mode from {pattern['verify_mode']} to 0 (SSL_VERIFY_NONE)",
                    'confidence': pattern.get('confidence', 'low')
                })
        
        return patches


def main():
    print("""
╔══════════════════════════════════════════════════════════════╗
║     Dead Space 2 SSL Pattern Finder                          ║
║                                                              ║
║  Deep analysis of activation.x86.dll to find SSL            ║
║  certificate verification patterns.                         ║
╚══════════════════════════════════════════════════════════════╝
    """)
    
    if len(sys.argv) < 2:
        print("Usage: python ssl_pattern_finder.py <path_to_dll>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        sys.exit(1)
    
    print(f"[+] Loading: {filepath}")
    
    with open(filepath, 'rb') as f:
        data = f.read()
    
    print(f"[+] Size: {len(data)} bytes")
    
    # Parse PE
    print("\n[*] Parsing PE structure...")
    pe = PEAnalyzer(data)
    if not pe.parse():
        sys.exit(1)
    
    # Find SSL patterns
    finder = SSLPatternFinder(data, pe)
    results = finder.analyze()
    
    # Summary
    print("\n" + "="*60)
    print("SUMMARY")
    print("="*60)
    print(f"SSL strings found: {len(results['ssl_strings'])}")
    print(f"Verify call patterns: {len(results['verify_patterns'])}")
    print(f"Callback candidates: {len(results['callback_candidates'])}")
    print(f"Error string references: {len(results['error_strings'])}")
    
    # Generate patch suggestions
    if results['verify_patterns']:
        print("\n" + "="*60)
        print("SUGGESTED PATCHES")
        print("="*60)
        
        for i, pattern in enumerate(results['verify_patterns'][:5]):
            print(f"\nPatch {i+1}:")
            print(f"  File offset: 0x{pattern['file_offset']:08X}")
            print(f"  Change byte at offset 0x{pattern['file_offset']+1:08X}")
            print(f"  From: 0x{pattern['verify_mode']:02X} to 0x00")
            print(f"  Effect: {finder._mode_name(pattern['verify_mode'])} -> SSL_VERIFY_NONE")


if __name__ == "__main__":
    main()
