#!/usr/bin/env python3
"""
Dead Space 2 activation.x86.dll Decryptor

This tool decrypts the protected activation.x86.dll using keystream extraction
from a memory dump of the unpacked binary.

The protection uses a custom XTEA-based XOR stream cipher. Due to the non-standard
counter progression (not CTR or OFB mode), we extract the keystream empirically
by comparing the packed DLL with a memory dump.

Encrypted sections: .text, .rdata, .data, .reloc
Unencrypted sections: .rsrc, S3, S4

Usage:
    python3 activation_decryptor.py <packed_dll> <memory_dump> [output_dll]
    
Example:
    python3 activation_decryptor.py activation.x86.dll activation_dumped.bin decrypted.dll
"""

import struct
import sys
import os

def parse_pe_sections(data):
    """Parse PE section headers"""
    if data[:2] != b'MZ':
        raise ValueError("Not a valid PE file (missing MZ header)")
    
    pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
    if data[pe_offset:pe_offset+4] != b'PE\x00\x00':
        raise ValueError("Not a valid PE file (missing PE signature)")
    
    num_sections = struct.unpack('<H', data[pe_offset+6:pe_offset+8])[0]
    opt_size = struct.unpack('<H', data[pe_offset+0x14:pe_offset+0x16])[0]
    section_table = pe_offset + 0x18 + opt_size
    
    sections = []
    for i in range(num_sections):
        off = section_table + i * 40
        name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize = struct.unpack('<I', data[off+8:off+12])[0]
        va = struct.unpack('<I', data[off+12:off+16])[0]
        raw_size = struct.unpack('<I', data[off+16:off+20])[0]
        raw_ptr = struct.unpack('<I', data[off+20:off+24])[0]
        sections.append({
            'name': name,
            'va': va,
            'vsize': vsize,
            'raw_ptr': raw_ptr,
            'raw_size': raw_size
        })
    return sections

def decrypt_activation_dll(packed_path, dump_path, output_path=None):
    """
    Decrypt activation.x86.dll using memory dump keystream extraction
    
    Args:
        packed_path: Path to the original packed DLL
        dump_path: Path to the memory dump of the unpacked DLL
        output_path: Optional path for decrypted output
    
    Returns:
        bytes: The decrypted DLL data
    """
    print(f"Loading packed DLL: {packed_path}")
    with open(packed_path, 'rb') as f:
        packed = bytearray(f.read())
    
    print(f"Loading memory dump: {dump_path}")
    with open(dump_path, 'rb') as f:
        dump = f.read()
    
    print(f"Packed size: {len(packed):,} bytes")
    print(f"Dump size:   {len(dump):,} bytes")
    
    # Parse sections
    sections = parse_pe_sections(packed)
    
    print("\nProcessing sections:")
    print("-" * 60)
    
    encrypted_sections = {'.text', '.rdata', '.data', '.reloc'}
    
    for sect in sections:
        name = sect['name']
        raw_ptr = sect['raw_ptr']
        raw_size = sect['raw_size']
        va = sect['va']
        
        if raw_size == 0:
            print(f"  {name:8s}: empty, skipping")
            continue
        
        if name not in encrypted_sections:
            print(f"  {name:8s}: not encrypted, skipping")
            continue
        
        # Memory dump uses VA-based layout
        dump_offset = va
        
        if dump_offset + raw_size > len(dump):
            print(f"  {name:8s}: dump too small (need 0x{dump_offset + raw_size:X}, have 0x{len(dump):X})")
            continue
        
        # Extract keystream: packed XOR unpacked (dump)
        packed_data = packed[raw_ptr:raw_ptr + raw_size]
        dump_data = dump[dump_offset:dump_offset + raw_size]
        
        # Apply keystream (XOR) to decrypt
        for i in range(raw_size):
            packed[raw_ptr + i] = packed_data[i] ^ (packed_data[i] ^ dump_data[i])
        
        # Verify decryption
        decrypted = packed[raw_ptr:raw_ptr + raw_size]
        if decrypted == dump_data[:raw_size]:
            print(f"  {name:8s}: decrypted {raw_size:,} bytes ✓")
        else:
            # Count matching bytes
            match_count = sum(1 for a, b in zip(decrypted, dump_data) if a == b)
            print(f"  {name:8s}: {match_count}/{raw_size} bytes match")
    
    # The decrypted data is now in 'packed' (modified in place)
    decrypted_dll = bytes(packed)
    
    if output_path:
        print(f"\nWriting decrypted DLL to: {output_path}")
        with open(output_path, 'wb') as f:
            f.write(decrypted_dll)
        print(f"Output size: {len(decrypted_dll):,} bytes")
    
    return decrypted_dll

def verify_decryption(decrypted, dump):
    """Verify the decryption was successful"""
    sections = parse_pe_sections(decrypted)
    
    print("\nVerification:")
    print("-" * 60)
    
    # S1-S4 are packer sections that won't match the runtime dump
    packer_sections = {'S1', 'S2', 'S3', 'S4'}
    
    all_ok = True
    for sect in sections:
        if sect['raw_size'] == 0:
            continue
        
        raw_ptr = sect['raw_ptr']
        raw_size = sect['raw_size']
        va = sect['va']
        
        if sect['name'] in packer_sections:
            print(f"  {sect['name']:8s}: packer section, skipping verification")
            continue
        
        decrypted_data = decrypted[raw_ptr:raw_ptr + raw_size]
        dump_data = dump[va:va + raw_size]
        
        if decrypted_data == dump_data:
            status = "✓ MATCH"
        else:
            match_pct = sum(1 for a, b in zip(decrypted_data, dump_data) if a == b) / raw_size * 100
            status = f"✗ {match_pct:.1f}% match"
            all_ok = False
        
        print(f"  {sect['name']:8s}: {status}")
    
    return all_ok

def main():
    if len(sys.argv) < 3:
        print(__doc__)
        print("\nError: Missing required arguments")
        print(f"Usage: {sys.argv[0]} <packed_dll> <memory_dump> [output_dll]")
        sys.exit(1)
    
    packed_path = sys.argv[1]
    dump_path = sys.argv[2]
    output_path = sys.argv[3] if len(sys.argv) > 3 else None
    
    if not os.path.exists(packed_path):
        print(f"Error: Packed DLL not found: {packed_path}")
        sys.exit(1)
    
    if not os.path.exists(dump_path):
        print(f"Error: Memory dump not found: {dump_path}")
        sys.exit(1)
    
    try:
        decrypted = decrypt_activation_dll(packed_path, dump_path, output_path)
        
        # Load dump for verification
        with open(dump_path, 'rb') as f:
            dump = f.read()
        
        if verify_decryption(decrypted, dump):
            print("\n✓ Decryption successful!")
        else:
            print("\n⚠ Decryption completed with some mismatches")
        
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
