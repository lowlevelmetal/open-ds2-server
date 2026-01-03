#!/usr/bin/env python3
"""
Deep Reverse Engineering Analysis for Dead Space 2 activation.x86.dll

This tool performs comprehensive analysis to find the exact SSL verification
code that needs to be patched, using multiple techniques:

1. Import table analysis - find OpenSSL function imports
2. String cross-reference analysis - find certificate error handlers  
3. Function signature matching - identify SSL_CTX_set_verify calls
4. Control flow analysis - trace the verification path
"""

import sys
import os
import struct
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass
from collections import defaultdict


@dataclass
class PESection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_address: int
    raw_size: int
    characteristics: int


@dataclass 
class ImportEntry:
    dll_name: str
    function_name: str
    ordinal: int
    hint: int
    thunk_rva: int


@dataclass
class ExportEntry:
    name: str
    ordinal: int
    rva: int


class DeepAnalyzer:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.data = None
        self.sections: List[PESection] = []
        self.imports: Dict[str, List[ImportEntry]] = defaultdict(list)
        self.exports: List[ExportEntry] = []
        self.image_base = 0
        self.strings: Dict[int, str] = {}  # offset -> string
        self.xrefs: Dict[int, List[int]] = defaultdict(list)  # target -> sources
        
    def load(self) -> bool:
        with open(self.filepath, 'rb') as f:
            self.data = bytearray(f.read())
        print(f"[+] Loaded {len(self.data)} bytes")
        return True
    
    def parse_pe(self) -> bool:
        """Parse PE headers, sections, imports, exports."""
        if self.data[:2] != b'MZ':
            print("[-] Not a valid PE file")
            return False
        
        pe_offset = struct.unpack('<I', self.data[0x3C:0x40])[0]
        if self.data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            print("[-] Invalid PE signature")
            return False
        
        # COFF header
        coff = pe_offset + 4
        num_sections = struct.unpack('<H', self.data[coff+2:coff+4])[0]
        opt_header_size = struct.unpack('<H', self.data[coff+16:coff+18])[0]
        
        # Optional header
        opt = coff + 20
        magic = struct.unpack('<H', self.data[opt:opt+2])[0]
        
        if magic == 0x10b:  # PE32
            self.image_base = struct.unpack('<I', self.data[opt+28:opt+32])[0]
            num_rva_sizes = struct.unpack('<I', self.data[opt+92:opt+96])[0]
            data_dir_offset = opt + 96
        else:
            print("[-] Only PE32 supported")
            return False
        
        print(f"[+] Image base: 0x{self.image_base:08X}")
        
        # Data directories
        export_rva = struct.unpack('<I', self.data[data_dir_offset:data_dir_offset+4])[0]
        export_size = struct.unpack('<I', self.data[data_dir_offset+4:data_dir_offset+8])[0]
        import_rva = struct.unpack('<I', self.data[data_dir_offset+8:data_dir_offset+12])[0]
        import_size = struct.unpack('<I', self.data[data_dir_offset+12:data_dir_offset+16])[0]
        
        # Parse sections
        sec_offset = opt + opt_header_size
        for i in range(num_sections):
            sec = sec_offset + i * 40
            name = self.data[sec:sec+8].rstrip(b'\x00').decode('utf-8', errors='ignore')
            vsize = struct.unpack('<I', self.data[sec+8:sec+12])[0]
            vaddr = struct.unpack('<I', self.data[sec+12:sec+16])[0]
            rsize = struct.unpack('<I', self.data[sec+16:sec+20])[0]
            raddr = struct.unpack('<I', self.data[sec+20:sec+24])[0]
            chars = struct.unpack('<I', self.data[sec+36:sec+40])[0]
            
            self.sections.append(PESection(name, vaddr, vsize, raddr, rsize, chars))
        
        # Parse imports
        if import_rva:
            self._parse_imports(import_rva)
        
        # Parse exports
        if export_rva:
            self._parse_exports(export_rva)
        
        return True
    
    def _parse_imports(self, import_rva: int):
        """Parse import directory."""
        offset = self.rva_to_offset(import_rva)
        if offset is None:
            return
        
        while True:
            # Import descriptor: 5 DWORDs
            ilt_rva = struct.unpack('<I', self.data[offset:offset+4])[0]
            timestamp = struct.unpack('<I', self.data[offset+4:offset+8])[0]
            forwarder = struct.unpack('<I', self.data[offset+8:offset+12])[0]
            name_rva = struct.unpack('<I', self.data[offset+12:offset+16])[0]
            iat_rva = struct.unpack('<I', self.data[offset+16:offset+20])[0]
            
            if name_rva == 0:
                break
            
            # Get DLL name
            name_offset = self.rva_to_offset(name_rva)
            dll_name = self._read_string(name_offset)
            
            # Parse import entries
            if ilt_rva:
                thunk_offset = self.rva_to_offset(ilt_rva)
            else:
                thunk_offset = self.rva_to_offset(iat_rva)
            
            iat_offset = self.rva_to_offset(iat_rva)
            thunk_idx = 0
            
            while thunk_offset:
                thunk = struct.unpack('<I', self.data[thunk_offset:thunk_offset+4])[0]
                if thunk == 0:
                    break
                
                if thunk & 0x80000000:  # Ordinal
                    ordinal = thunk & 0xFFFF
                    func_name = f"Ordinal_{ordinal}"
                    hint = 0
                else:
                    hint_name_offset = self.rva_to_offset(thunk)
                    hint = struct.unpack('<H', self.data[hint_name_offset:hint_name_offset+2])[0]
                    func_name = self._read_string(hint_name_offset + 2)
                    ordinal = 0
                
                entry = ImportEntry(dll_name, func_name, ordinal, hint, iat_rva + thunk_idx * 4)
                self.imports[dll_name.lower()].append(entry)
                
                thunk_offset += 4
                thunk_idx += 1
            
            offset += 20
    
    def _parse_exports(self, export_rva: int):
        """Parse export directory."""
        offset = self.rva_to_offset(export_rva)
        if offset is None:
            return
        
        num_functions = struct.unpack('<I', self.data[offset+20:offset+24])[0]
        num_names = struct.unpack('<I', self.data[offset+24:offset+28])[0]
        addr_table_rva = struct.unpack('<I', self.data[offset+28:offset+32])[0]
        name_table_rva = struct.unpack('<I', self.data[offset+32:offset+36])[0]
        ordinal_table_rva = struct.unpack('<I', self.data[offset+36:offset+40])[0]
        ordinal_base = struct.unpack('<I', self.data[offset+16:offset+20])[0]
        
        addr_offset = self.rva_to_offset(addr_table_rva)
        name_offset = self.rva_to_offset(name_table_rva)
        ordinal_offset = self.rva_to_offset(ordinal_table_rva)
        
        for i in range(num_names):
            name_rva = struct.unpack('<I', self.data[name_offset + i*4:name_offset + i*4 + 4])[0]
            ordinal_idx = struct.unpack('<H', self.data[ordinal_offset + i*2:ordinal_offset + i*2 + 2])[0]
            func_rva = struct.unpack('<I', self.data[addr_offset + ordinal_idx*4:addr_offset + ordinal_idx*4 + 4])[0]
            
            name_str_offset = self.rva_to_offset(name_rva)
            name = self._read_string(name_str_offset)
            
            self.exports.append(ExportEntry(name, ordinal_base + ordinal_idx, func_rva))
    
    def _read_string(self, offset: int, max_len: int = 256) -> str:
        """Read null-terminated string."""
        if offset is None or offset >= len(self.data):
            return ""
        end = min(offset + max_len, len(self.data))
        result = []
        for i in range(offset, end):
            if self.data[i] == 0:
                break
            result.append(chr(self.data[i]))
        return ''.join(result)
    
    def rva_to_offset(self, rva: int) -> Optional[int]:
        """Convert RVA to file offset."""
        for s in self.sections:
            if s.virtual_address <= rva < s.virtual_address + s.virtual_size:
                return rva - s.virtual_address + s.raw_address
        return None
    
    def offset_to_rva(self, offset: int) -> Optional[int]:
        """Convert file offset to RVA."""
        for s in self.sections:
            if s.raw_address <= offset < s.raw_address + s.raw_size:
                return offset - s.raw_address + s.virtual_address
        return None
    
    def find_strings(self, min_length: int = 4) -> Dict[int, str]:
        """Extract printable strings from the binary."""
        strings = {}
        current = []
        start = 0
        
        for i, b in enumerate(self.data):
            if 32 <= b < 127:
                if not current:
                    start = i
                current.append(chr(b))
            else:
                if len(current) >= min_length:
                    strings[start] = ''.join(current)
                current = []
        
        return strings
    
    def find_ssl_related_strings(self) -> List[Tuple[int, str]]:
        """Find strings related to SSL/certificate verification."""
        keywords = [
            'ssl', 'SSL', 'certificate', 'verify', 'cert', 'x509', 'X509',
            'openssl', 'OpenSSL', 'handshake', 'peer', 'issuer', 'chain',
            'trust', 'valid', 'expired', 'self.signed', 'CA', 'root',
            'gosredirector', 'ea.com', 'blaze', 'Blaze'
        ]
        
        if not self.strings:
            self.strings = self.find_strings()
        
        results = []
        for offset, s in self.strings.items():
            for kw in keywords:
                if kw.lower() in s.lower():
                    results.append((offset, s))
                    break
        
        return results
    
    def find_xrefs_to_address(self, target_va: int) -> List[int]:
        """Find cross-references to a virtual address."""
        xrefs = []
        target_bytes = struct.pack('<I', target_va)
        
        pos = 0
        while True:
            idx = self.data.find(target_bytes, pos)
            if idx == -1:
                break
            xrefs.append(idx)
            pos = idx + 1
        
        return xrefs
    
    def find_call_to_address(self, target_rva: int) -> List[int]:
        """Find CALL instructions to a specific RVA."""
        calls = []
        
        for section in self.sections:
            if not (section.characteristics & 0x20000000):  # Not executable
                continue
            
            start = section.raw_address
            end = start + section.raw_size
            
            for i in range(start, end - 5):
                if self.data[i] == 0xE8:  # CALL rel32
                    rel = struct.unpack('<i', self.data[i+1:i+5])[0]
                    call_rva = self.offset_to_rva(i)
                    if call_rva:
                        dest_rva = call_rva + 5 + rel
                        if dest_rva == target_rva:
                            calls.append(i)
        
        return calls
    
    def analyze_function_at(self, offset: int, max_bytes: int = 256) -> Dict:
        """Analyze a function starting at the given offset."""
        result = {
            'offset': offset,
            'rva': self.offset_to_rva(offset),
            'instructions': [],
            'calls': [],
            'pushes': [],
            'strings_referenced': []
        }
        
        end = min(offset + max_bytes, len(self.data))
        i = offset
        
        while i < end:
            byte = self.data[i]
            
            # Simple x86 instruction parsing
            if byte == 0xC3:  # RET
                result['instructions'].append((i, 'ret'))
                break
            elif byte == 0xC2:  # RET imm16
                result['instructions'].append((i, f'ret {struct.unpack("<H", self.data[i+1:i+3])[0]}'))
                i += 3
                continue
            elif byte == 0xE8:  # CALL rel32
                rel = struct.unpack('<i', self.data[i+1:i+5])[0]
                rva = self.offset_to_rva(i)
                if rva:
                    target = rva + 5 + rel
                    result['calls'].append((i, target))
                    result['instructions'].append((i, f'call 0x{target:08X}'))
                i += 5
                continue
            elif byte == 0x6A:  # PUSH imm8
                val = self.data[i+1]
                result['pushes'].append((i, val, 'imm8'))
                result['instructions'].append((i, f'push {val}'))
                i += 2
                continue
            elif byte == 0x68:  # PUSH imm32
                val = struct.unpack('<I', self.data[i+1:i+5])[0]
                result['pushes'].append((i, val, 'imm32'))
                result['instructions'].append((i, f'push 0x{val:08X}'))
                # Check if this is a string reference
                if self.image_base <= val < self.image_base + 0x1000000:
                    str_rva = val - self.image_base
                    str_offset = self.rva_to_offset(str_rva)
                    if str_offset:
                        s = self._read_string(str_offset)
                        if s and len(s) > 3:
                            result['strings_referenced'].append((i, val, s))
                i += 5
                continue
            elif byte == 0xFF:  # Various
                modrm = self.data[i+1]
                reg = (modrm >> 3) & 7
                if reg == 2:  # CALL r/m32
                    result['instructions'].append((i, 'call indirect'))
                i += 2
                continue
            
            i += 1
        
        return result
    
    def find_ssl_ctx_set_verify(self) -> List[Dict]:
        """
        Find SSL_CTX_set_verify calls by looking for the pattern:
        - The function is typically imported or statically linked
        - Called with (ctx, mode, callback) parameters
        - Mode is 0-3 (SSL_VERIFY_NONE to SSL_VERIFY_PEER|FAIL_IF_NO_PEER_CERT)
        """
        candidates = []
        
        # First check if SSL functions are imported
        ssl_imports = []
        for dll, entries in self.imports.items():
            for entry in entries:
                if 'ssl' in entry.function_name.lower() or 'SSL' in entry.function_name:
                    ssl_imports.append(entry)
        
        if ssl_imports:
            print(f"\n[+] Found {len(ssl_imports)} SSL-related imports:")
            for imp in ssl_imports:
                print(f"    {imp.dll_name}!{imp.function_name} @ IAT RVA 0x{imp.thunk_rva:08X}")
        
        # Check for SSL exports (if this DLL exports OpenSSL functions)
        ssl_exports = [e for e in self.exports if 'ssl' in e.name.lower() or 'SSL' in e.name]
        if ssl_exports:
            print(f"\n[+] Found {len(ssl_exports)} SSL-related exports:")
            for exp in ssl_exports[:20]:
                print(f"    {exp.name} @ RVA 0x{exp.rva:08X}")
        
        # Look for SSL_CTX_set_verify specifically
        verify_export = None
        for exp in self.exports:
            if exp.name == 'SSL_CTX_set_verify':
                verify_export = exp
                break
        
        if verify_export:
            print(f"\n[+] Found SSL_CTX_set_verify export at RVA 0x{verify_export.rva:08X}")
            # Find all calls to this function
            calls = self.find_call_to_address(verify_export.rva)
            print(f"[+] Found {len(calls)} calls to SSL_CTX_set_verify")
            
            for call_offset in calls:
                # Analyze the context around this call
                # Look backwards for the push instructions that set up parameters
                context_start = max(0, call_offset - 32)
                context = self.data[context_start:call_offset+5]
                
                # Find push instructions in the context
                pushes = []
                j = 0
                while j < len(context) - 1:
                    if context[j] == 0x6A:  # push imm8
                        pushes.append((context_start + j, context[j+1], 'imm8'))
                        j += 2
                    elif context[j] == 0x68:  # push imm32
                        val = struct.unpack('<I', context[j+1:j+5])[0]
                        pushes.append((context_start + j, val, 'imm32'))
                        j += 5
                    else:
                        j += 1
                
                # The verify mode is typically the second-to-last push before the call
                # (callback is last, mode is second, ctx is first)
                candidates.append({
                    'call_offset': call_offset,
                    'call_rva': self.offset_to_rva(call_offset),
                    'pushes': pushes,
                    'context': context.hex()
                })
        
        return candidates
    
    def find_certificate_verify_callback(self) -> List[Dict]:
        """
        Find the SSL certificate verify callback function.
        
        The callback has signature: int callback(int preverify_ok, X509_STORE_CTX *ctx)
        - It receives preverify_ok as first param
        - Should return 1 to accept, 0 to reject
        
        We look for small functions that:
        - Are referenced as a callback parameter to SSL_CTX_set_verify
        - Return 0 or 1
        - May check preverify_ok parameter
        """
        callbacks = []
        
        # First find SSL_CTX_set_verify calls
        verify_calls = self.find_ssl_ctx_set_verify()
        
        for call_info in verify_calls:
            # Look for the callback parameter (last push before call)
            pushes = call_info['pushes']
            if len(pushes) >= 3:
                # Last push is likely the callback
                callback_push = pushes[-1]
                if callback_push[2] == 'imm32':
                    callback_va = callback_push[1]
                    if self.image_base <= callback_va < self.image_base + 0x1000000:
                        callback_rva = callback_va - self.image_base
                        callback_offset = self.rva_to_offset(callback_rva)
                        
                        if callback_offset:
                            # Analyze the callback function
                            func_info = self.analyze_function_at(callback_offset)
                            func_info['referenced_from'] = call_info['call_offset']
                            callbacks.append(func_info)
        
        return callbacks
    
    def deep_analysis(self):
        """Perform comprehensive analysis."""
        print("\n" + "="*70)
        print("DEEP REVERSE ENGINEERING ANALYSIS")
        print("="*70)
        
        # 1. Parse PE
        print("\n[1] Parsing PE structure...")
        if not self.parse_pe():
            return
        
        print(f"\n    Sections:")
        for s in self.sections:
            flags = []
            if s.characteristics & 0x20: flags.append('CODE')
            if s.characteristics & 0x20000000: flags.append('EXEC')
            if s.characteristics & 0x40000000: flags.append('READ')
            if s.characteristics & 0x80000000: flags.append('WRITE')
            print(f"      {s.name:8s} RVA:0x{s.virtual_address:08X} "
                  f"Size:{s.virtual_size:8d} [{','.join(flags)}]")
        
        # 2. Analyze imports
        print(f"\n[2] Import analysis...")
        print(f"    Total DLLs: {len(self.imports)}")
        for dll, entries in sorted(self.imports.items()):
            print(f"    {dll}: {len(entries)} imports")
        
        # 3. Analyze exports  
        print(f"\n[3] Export analysis...")
        print(f"    Total exports: {len(self.exports)}")
        
        # Look for OpenSSL exports
        openssl_exports = [e for e in self.exports if any(x in e.name for x in 
            ['SSL_', 'ssl_', 'X509', 'EVP_', 'BIO_', 'RSA_', 'CRYPTO_', 'OpenSSL'])]
        
        if openssl_exports:
            print(f"\n[+] This DLL exports OpenSSL functions! ({len(openssl_exports)} functions)")
            print("    This means OpenSSL is statically linked into the DLL.")
            
            # Find key functions
            key_funcs = ['SSL_CTX_set_verify', 'SSL_set_verify', 'SSL_CTX_new', 
                        'SSL_connect', 'X509_verify_cert', 'SSL_CTX_set_cert_verify_callback']
            
            print("\n    Key SSL functions:")
            for func_name in key_funcs:
                for exp in self.exports:
                    if exp.name == func_name:
                        offset = self.rva_to_offset(exp.rva)
                        print(f"      {func_name}: RVA 0x{exp.rva:08X}, Offset 0x{offset:08X}")
                        break
        
        # 4. Find SSL_CTX_set_verify calls
        print(f"\n[4] Finding SSL_CTX_set_verify calls...")
        verify_calls = self.find_ssl_ctx_set_verify()
        
        if verify_calls:
            print(f"\n[+] Found {len(verify_calls)} calls to SSL_CTX_set_verify:")
            for i, call in enumerate(verify_calls):
                print(f"\n    Call {i+1}:")
                print(f"      Offset: 0x{call['call_offset']:08X}")
                print(f"      RVA: 0x{call['call_rva']:08X}")
                print(f"      Context bytes: {call['context']}")
                print(f"      Push instructions found:")
                for push in call['pushes']:
                    offset, val, typ = push
                    if typ == 'imm8':
                        if val in [0, 1, 2, 3]:
                            mode_name = ['SSL_VERIFY_NONE', 'SSL_VERIFY_PEER', 
                                        'SSL_VERIFY_FAIL_IF_NO_PEER_CERT',
                                        'SSL_VERIFY_PEER|FAIL'][val]
                            print(f"        0x{offset:08X}: push {val} ({mode_name}) <-- PATCH THIS")
                        else:
                            print(f"        0x{offset:08X}: push {val}")
                    else:
                        print(f"        0x{offset:08X}: push 0x{val:08X}")
        
        # 5. Find SSL-related strings
        print(f"\n[5] Finding SSL-related strings...")
        ssl_strings = self.find_ssl_related_strings()
        if ssl_strings:
            print(f"    Found {len(ssl_strings)} SSL-related strings:")
            for offset, s in ssl_strings[:30]:
                rva = self.offset_to_rva(offset)
                print(f"      0x{offset:08X} (RVA 0x{rva:08X}): {s[:60]}")
        
        # 6. Find verify callbacks
        print(f"\n[6] Analyzing verify callbacks...")
        callbacks = self.find_certificate_verify_callback()
        if callbacks:
            print(f"    Found {len(callbacks)} potential verify callbacks:")
            for cb in callbacks:
                print(f"\n    Callback at offset 0x{cb['offset']:08X}:")
                print(f"      Referenced from: 0x{cb['referenced_from']:08X}")
                print(f"      Instructions:")
                for off, instr in cb['instructions'][:10]:
                    print(f"        0x{off:08X}: {instr}")
        
        # 7. Generate patch recommendations
        print("\n" + "="*70)
        print("PATCH RECOMMENDATIONS")
        print("="*70)
        
        if verify_calls:
            print("\nMethod 1: Patch SSL_CTX_set_verify mode parameter")
            print("-" * 50)
            for i, call in enumerate(verify_calls):
                # Find the mode push (value 1, 2, or 3)
                for push in call['pushes']:
                    offset, val, typ = push
                    if typ == 'imm8' and val in [1, 2, 3]:
                        patch_offset = offset + 1  # +1 to skip the 0x6A opcode
                        print(f"\nPatch {i+1}:")
                        print(f"  File offset: 0x{patch_offset:08X}")
                        print(f"  Original byte: 0x{val:02X}")
                        print(f"  Patched byte: 0x00")
                        print(f"  Command: printf '\\x00' | dd of=\"activation.x86.dll\" bs=1 seek=$((0x{patch_offset:X})) conv=notrunc")


def main():
    if len(sys.argv) < 2:
        print("Usage: python deep_analysis.py <activation.x86.dll>")
        sys.exit(1)
    
    filepath = sys.argv[1]
    if not os.path.exists(filepath):
        print(f"[-] File not found: {filepath}")
        sys.exit(1)
    
    analyzer = DeepAnalyzer(filepath)
    analyzer.load()
    analyzer.deep_analysis()


if __name__ == "__main__":
    main()
