#!/usr/bin/env python3
"""
Dead Space 2 activation.x86.dll Analyzer

Comprehensive analysis tool for the decrypted DLL.
Extracts function information, identifies SSL callbacks, and documents findings.
"""

import struct
import sys
import os
import re
from collections import defaultdict

class DLLAnalyzer:
    def __init__(self, dll_path):
        self.dll_path = dll_path
        with open(dll_path, 'rb') as f:
            self.data = f.read()
        self.sections = self._parse_pe_sections()
        self.exports = self._parse_exports()
        self.imports = self._parse_imports()
        self.strings = self._extract_strings()
        
    def _parse_pe_sections(self):
        """Parse PE section headers"""
        if self.data[:2] != b'MZ':
            raise ValueError("Not a valid PE file")
        
        pe_offset = struct.unpack('<I', self.data[0x3C:0x40])[0]
        if self.data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            raise ValueError("Invalid PE signature")
        
        num_sections = struct.unpack('<H', self.data[pe_offset+6:pe_offset+8])[0]
        opt_size = struct.unpack('<H', self.data[pe_offset+0x14:pe_offset+0x16])[0]
        
        # Get image base
        self.image_base = struct.unpack('<I', self.data[pe_offset+0x34:pe_offset+0x38])[0]
        
        section_table = pe_offset + 0x18 + opt_size
        
        sections = []
        for i in range(num_sections):
            off = section_table + i * 40
            name = self.data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
            vsize = struct.unpack('<I', self.data[off+8:off+12])[0]
            va = struct.unpack('<I', self.data[off+12:off+16])[0]
            raw_size = struct.unpack('<I', self.data[off+16:off+20])[0]
            raw_ptr = struct.unpack('<I', self.data[off+20:off+24])[0]
            characteristics = struct.unpack('<I', self.data[off+36:off+40])[0]
            sections.append({
                'name': name,
                'va': va,
                'vsize': vsize,
                'raw_ptr': raw_ptr,
                'raw_size': raw_size,
                'characteristics': characteristics
            })
        return sections
    
    def _parse_exports(self):
        """Parse export directory"""
        pe_offset = struct.unpack('<I', self.data[0x3C:0x40])[0]
        export_rva = struct.unpack('<I', self.data[pe_offset+0x78:pe_offset+0x7C])[0]
        export_size = struct.unpack('<I', self.data[pe_offset+0x7C:pe_offset+0x80])[0]
        
        if export_rva == 0:
            return []
        
        export_raw = self._rva_to_raw(export_rva)
        
        num_functions = struct.unpack('<I', self.data[export_raw+0x14:export_raw+0x18])[0]
        num_names = struct.unpack('<I', self.data[export_raw+0x18:export_raw+0x1C])[0]
        addr_table_rva = struct.unpack('<I', self.data[export_raw+0x1C:export_raw+0x20])[0]
        name_table_rva = struct.unpack('<I', self.data[export_raw+0x20:export_raw+0x24])[0]
        ordinal_table_rva = struct.unpack('<I', self.data[export_raw+0x24:export_raw+0x28])[0]
        ordinal_base = struct.unpack('<I', self.data[export_raw+0x10:export_raw+0x14])[0]
        
        exports = []
        for i in range(num_names):
            name_ptr_raw = self._rva_to_raw(name_table_rva) + i * 4
            name_rva = struct.unpack('<I', self.data[name_ptr_raw:name_ptr_raw+4])[0]
            name_raw = self._rva_to_raw(name_rva)
            
            # Find null terminator
            name_end = self.data.find(b'\x00', name_raw)
            name = self.data[name_raw:name_end].decode('ascii', errors='replace')
            
            ordinal_raw = self._rva_to_raw(ordinal_table_rva) + i * 2
            ordinal = struct.unpack('<H', self.data[ordinal_raw:ordinal_raw+2])[0]
            
            addr_raw = self._rva_to_raw(addr_table_rva) + ordinal * 4
            func_rva = struct.unpack('<I', self.data[addr_raw:addr_raw+4])[0]
            
            exports.append({
                'name': name,
                'ordinal': ordinal + ordinal_base,
                'rva': func_rva,
                'va': func_rva + self.image_base
            })
        
        return exports
    
    def _parse_imports(self):
        """Parse import directory"""
        pe_offset = struct.unpack('<I', self.data[0x3C:0x40])[0]
        import_rva = struct.unpack('<I', self.data[pe_offset+0x80:pe_offset+0x84])[0]
        
        if import_rva == 0:
            return {}
        
        imports = {}
        import_raw = self._rva_to_raw(import_rva)
        
        while True:
            name_rva = struct.unpack('<I', self.data[import_raw+12:import_raw+16])[0]
            if name_rva == 0:
                break
            
            name_raw = self._rva_to_raw(name_rva)
            name_end = self.data.find(b'\x00', name_raw)
            dll_name = self.data[name_raw:name_end].decode('ascii', errors='replace')
            
            imports[dll_name] = []
            import_raw += 20
        
        return imports
    
    def _rva_to_raw(self, rva):
        """Convert RVA to raw file offset"""
        for sect in self.sections:
            if sect['va'] <= rva < sect['va'] + sect['raw_size']:
                return rva - sect['va'] + sect['raw_ptr']
        return rva  # Fallback
    
    def _extract_strings(self, min_len=8):
        """Extract ASCII strings from the binary"""
        strings = []
        current = b''
        start_offset = 0
        
        for i, byte in enumerate(self.data):
            if 0x20 <= byte <= 0x7E:
                if len(current) == 0:
                    start_offset = i
                current += bytes([byte])
            else:
                if len(current) >= min_len:
                    try:
                        s = current.decode('ascii')
                        strings.append((start_offset, s))
                    except:
                        pass
                current = b''
        
        return strings
    
    def find_ssl_callbacks(self):
        """Find potential SSL verify callbacks"""
        # Pattern: 55 8B EC 83 EC 20 A1 38 80 67 79 (from our patcher)
        pattern = bytes([0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x20, 0xA1, 0x38, 0x80, 0x67, 0x79])
        
        callbacks = []
        start = 0
        while True:
            pos = self.data.find(pattern, start)
            if pos == -1:
                break
            
            # Convert to RVA
            for sect in self.sections:
                if sect['raw_ptr'] <= pos < sect['raw_ptr'] + sect['raw_size']:
                    rva = pos - sect['raw_ptr'] + sect['va']
                    callbacks.append({
                        'raw_offset': pos,
                        'rva': rva,
                        'va': rva + self.image_base,
                        'section': sect['name']
                    })
                    break
            start = pos + 1
        
        return callbacks
    
    def find_function_prologues(self):
        """Find common x86 function prologues"""
        patterns = [
            (b'\x55\x8B\xEC', 'push ebp; mov ebp, esp'),
            (b'\x55\x89\xE5', 'push ebp; mov ebp, esp (gcc)'),
        ]
        
        functions = []
        for pattern, desc in patterns:
            start = 0
            while True:
                pos = self.data.find(pattern, start)
                if pos == -1:
                    break
                
                # Check if in .text section
                for sect in self.sections:
                    if sect['name'] == '.text' and sect['raw_ptr'] <= pos < sect['raw_ptr'] + sect['raw_size']:
                        rva = pos - sect['raw_ptr'] + sect['va']
                        functions.append({
                            'raw_offset': pos,
                            'rva': rva,
                            'va': rva + self.image_base,
                            'prologue': desc
                        })
                        break
                start = pos + 1
        
        return sorted(functions, key=lambda x: x['rva'])
    
    def find_crypto_constants(self):
        """Find cryptographic constants"""
        constants = {
            'AES S-box start': bytes([0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5]),
            'MD5 init': struct.pack('<4I', 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476),
            'SHA1 init': struct.pack('>5I', 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0),
            'SHA256 init': struct.pack('>8I', 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 
                                        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19),
        }
        
        found = []
        for name, pattern in constants.items():
            pos = self.data.find(pattern)
            if pos != -1:
                found.append({
                    'name': name,
                    'offset': pos,
                    'pattern': pattern.hex()
                })
        
        return found
    
    def categorize_strings(self):
        """Categorize strings by type"""
        categories = {
            'ssl_tls': [],
            'http': [],
            'crypto': [],
            'error': [],
            'authentication': [],
            'openssl': [],
            'other': []
        }
        
        patterns = {
            'ssl_tls': re.compile(r'(ssl|tls|cert|handshake|verify)', re.I),
            'http': re.compile(r'(http|ftp|smtp|pop3|imap|proxy|host)', re.I),
            'crypto': re.compile(r'(aes|rsa|sha|md5|encrypt|decrypt|cipher|pkcs|x509)', re.I),
            'error': re.compile(r'(error|fail|invalid|denied|abort)', re.I),
            'authentication': re.compile(r'(auth|login|password|credential|token)', re.I),
            'openssl': re.compile(r'openssl', re.I),
        }
        
        for offset, s in self.strings:
            categorized = False
            for cat, pattern in patterns.items():
                if pattern.search(s):
                    categories[cat].append((offset, s))
                    categorized = True
                    break
            if not categorized:
                categories['other'].append((offset, s))
        
        return categories
    
    def analyze_export_functions(self):
        """Analyze exported functions"""
        results = []
        
        for exp in self.exports:
            raw_offset = self._rva_to_raw(exp['rva'])
            
            # Read first 32 bytes of the function
            func_bytes = self.data[raw_offset:raw_offset+32]
            
            # Check for stub patterns
            is_stub = False
            stub_value = None
            
            # Pattern: mov eax, imm32; ret
            if func_bytes[:1] == b'\xB8' and func_bytes[5:6] == b'\xC3':
                is_stub = True
                stub_value = struct.unpack('<I', func_bytes[1:5])[0]
            
            results.append({
                'name': exp['name'],
                'ordinal': exp['ordinal'],
                'rva': exp['rva'],
                'va': exp['va'],
                'raw_offset': raw_offset,
                'first_bytes': func_bytes[:16].hex(),
                'is_stub': is_stub,
                'stub_value': stub_value
            })
        
        return results
    
    def generate_report(self):
        """Generate comprehensive analysis report"""
        report = []
        report.append("=" * 70)
        report.append("Dead Space 2 activation.x86.dll Analysis Report")
        report.append("=" * 70)
        report.append("")
        
        # Basic info
        report.append("## Binary Information")
        report.append(f"File: {self.dll_path}")
        report.append(f"Size: {len(self.data):,} bytes")
        report.append(f"Image Base: 0x{self.image_base:08X}")
        report.append("")
        
        # Sections
        report.append("## Sections")
        report.append("-" * 50)
        for sect in self.sections:
            flags = []
            if sect['characteristics'] & 0x20000000: flags.append('EXEC')
            if sect['characteristics'] & 0x40000000: flags.append('READ')
            if sect['characteristics'] & 0x80000000: flags.append('WRITE')
            report.append(f"  {sect['name']:8s} VA: 0x{sect['va']:08X}  "
                         f"Size: 0x{sect['raw_size']:06X}  [{', '.join(flags)}]")
        report.append("")
        
        # Exports
        report.append("## Exported Functions")
        report.append("-" * 50)
        exports = self.analyze_export_functions()
        for exp in exports:
            stub_info = ""
            if exp['is_stub']:
                stub_info = f" [STUB: 0x{exp['stub_value']:08X}]"
            report.append(f"  [{exp['ordinal']:2d}] {exp['name']:20s} RVA: 0x{exp['rva']:06X}{stub_info}")
        report.append("")
        
        # SSL Callbacks
        report.append("## SSL Verify Callbacks")
        report.append("-" * 50)
        callbacks = self.find_ssl_callbacks()
        if callbacks:
            for cb in callbacks:
                report.append(f"  Found at RVA 0x{cb['rva']:06X} (VA 0x{cb['va']:08X}) in {cb['section']}")
                report.append(f"    File offset: 0x{cb['raw_offset']:06X}")
        else:
            report.append("  No SSL verify callbacks found with known patterns")
        report.append("")
        
        # Crypto constants
        report.append("## Cryptographic Constants")
        report.append("-" * 50)
        crypto = self.find_crypto_constants()
        if crypto:
            for c in crypto:
                report.append(f"  {c['name']}: offset 0x{c['offset']:06X}")
        else:
            report.append("  No known crypto constants found")
        report.append("")
        
        # Categorized strings
        report.append("## String Analysis (Selected)")
        report.append("-" * 50)
        categories = self.categorize_strings()
        
        interesting_categories = ['ssl_tls', 'authentication', 'openssl', 'http']
        for cat in interesting_categories:
            if categories[cat]:
                report.append(f"\n### {cat.upper()} Strings:")
                for offset, s in categories[cat][:20]:  # First 20 strings
                    if len(s) > 60:
                        s = s[:57] + "..."
                    report.append(f"    0x{offset:06X}: {s}")
        report.append("")
        
        # Function statistics
        report.append("## Function Statistics")
        report.append("-" * 50)
        functions = self.find_function_prologues()
        report.append(f"  Total function prologues found: {len(functions)}")
        report.append("")
        
        # Imports
        report.append("## Imported DLLs")
        report.append("-" * 50)
        for dll in self.imports.keys():
            report.append(f"  {dll}")
        report.append("")
        
        return '\n'.join(report)


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 dll_analyzer.py <decrypted_dll> [output_report]")
        sys.exit(1)
    
    dll_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not os.path.exists(dll_path):
        print(f"Error: File not found: {dll_path}")
        sys.exit(1)
    
    print(f"Analyzing {dll_path}...")
    analyzer = DLLAnalyzer(dll_path)
    report = analyzer.generate_report()
    
    print(report)
    
    if output_path:
        with open(output_path, 'w') as f:
            f.write(report)
        print(f"\nReport saved to: {output_path}")


if __name__ == '__main__':
    main()
