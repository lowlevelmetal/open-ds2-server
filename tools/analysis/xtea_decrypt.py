#!/usr/bin/env python3
"""
Dead Space 2 activation.x86.dll Decryptor

This script decrypts the XTEA-encrypted sections of the activation.x86.dll file.

Based on reverse engineering of the unpacker stub at entry point 0x00109049.

Encryption Details:
- Algorithm: XTEA (Extended Tiny Encryption Algorithm)
- Key: 0x0614B34A, 0xF6BD5EC7, 0x408EC6B5, 0xE2E4D222
- Delta: 0x9E3779B9 (standard TEA constant)
- Block size: 64 bits (8 bytes)
- Rounds: 32 (standard XTEA)
"""

import struct
import sys
import os
from pathlib import Path

# XTEA Constants from the binary
XTEA_KEY = [0x0614B34A, 0xF6BD5EC7, 0x408EC6B5, 0xE2E4D222]
XTEA_DELTA = 0x9E3779B9
XTEA_ROUNDS = 32

def xtea_decrypt_block(v0, v1, key):
    """
    Decrypt a single 64-bit block using XTEA.
    
    Args:
        v0, v1: Two 32-bit values forming the 64-bit block
        key: List of 4 32-bit key values
    
    Returns:
        Tuple of (v0, v1) decrypted values
    """
    # Calculate final sum value (delta * rounds)
    sum_val = (XTEA_DELTA * XTEA_ROUNDS) & 0xFFFFFFFF
    
    for _ in range(XTEA_ROUNDS):
        # Reverse of encryption:
        # v1 -= ((v0<<4 ^ v0>>5) + v0) ^ (sum + key[(sum>>11) & 3])
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + key[(sum_val >> 11) & 3]))) & 0xFFFFFFFF
        
        sum_val = (sum_val - XTEA_DELTA) & 0xFFFFFFFF
        
        # v0 -= ((v1<<4 ^ v1>>5) + v1) ^ (sum + key[sum & 3])
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + key[sum_val & 3]))) & 0xFFFFFFFF
    
    return v0, v1


def xtea_encrypt_block(v0, v1, key):
    """
    Encrypt a single 64-bit block using XTEA.
    Used for verification.
    """
    sum_val = 0
    
    for _ in range(XTEA_ROUNDS):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + key[sum_val & 3]))) & 0xFFFFFFFF
        sum_val = (sum_val + XTEA_DELTA) & 0xFFFFFFFF
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + key[(sum_val >> 11) & 3]))) & 0xFFFFFFFF
    
    return v0, v1


def xtea_decrypt_data(data, key):
    """
    Decrypt a byte array using XTEA.
    
    Args:
        data: Bytes to decrypt (must be multiple of 8)
        key: List of 4 32-bit key values
    
    Returns:
        Decrypted bytes
    """
    if len(data) % 8 != 0:
        # Pad to 8-byte boundary
        data = data + b'\x00' * (8 - len(data) % 8)
    
    result = bytearray()
    
    for i in range(0, len(data), 8):
        v0, v1 = struct.unpack('<II', data[i:i+8])
        v0_dec, v1_dec = xtea_decrypt_block(v0, v1, key)
        result.extend(struct.pack('<II', v0_dec, v1_dec))
    
    return bytes(result)


def test_xtea():
    """Test XTEA implementation with known values."""
    print("Testing XTEA implementation...")
    
    # Test encrypt then decrypt
    test_v0, test_v1 = 0x12345678, 0x9ABCDEF0
    
    enc_v0, enc_v1 = xtea_encrypt_block(test_v0, test_v1, XTEA_KEY)
    dec_v0, dec_v1 = xtea_decrypt_block(enc_v0, enc_v1, XTEA_KEY)
    
    if dec_v0 == test_v0 and dec_v1 == test_v1:
        print("  [+] XTEA encrypt/decrypt roundtrip: PASS")
        return True
    else:
        print("  [-] XTEA encrypt/decrypt roundtrip: FAIL")
        print(f"      Expected: {test_v0:08X} {test_v1:08X}")
        print(f"      Got:      {dec_v0:08X} {dec_v1:08X}")
        return False


def parse_pe_sections(data):
    """Parse PE sections from file data."""
    
    if data[:2] != b'MZ':
        raise ValueError("Not a valid PE file (missing MZ signature)")
    
    e_lfanew = struct.unpack('<I', data[0x3c:0x40])[0]
    
    if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
        raise ValueError("Not a valid PE file (missing PE signature)")
    
    # COFF header
    coff_offset = e_lfanew + 4
    num_sections = struct.unpack('<H', data[coff_offset+2:coff_offset+4])[0]
    opt_header_size = struct.unpack('<H', data[coff_offset+16:coff_offset+18])[0]
    
    # Optional header
    opt_offset = coff_offset + 20
    
    # Section headers start after optional header
    section_offset = opt_offset + opt_header_size
    
    sections = []
    for i in range(num_sections):
        sec = section_offset + i * 40
        name = data[sec:sec+8].rstrip(b'\x00').decode('ascii', errors='replace')
        virt_size = struct.unpack('<I', data[sec+8:sec+12])[0]
        virt_addr = struct.unpack('<I', data[sec+12:sec+16])[0]
        raw_size = struct.unpack('<I', data[sec+16:sec+20])[0]
        raw_ptr = struct.unpack('<I', data[sec+20:sec+24])[0]
        characteristics = struct.unpack('<I', data[sec+36:sec+40])[0]
        
        sections.append({
            'name': name,
            'virt_size': virt_size,
            'virt_addr': virt_addr,
            'raw_size': raw_size,
            'raw_ptr': raw_ptr,
            'characteristics': characteristics
        })
    
    return sections


def calc_entropy(data):
    """Calculate Shannon entropy of data."""
    if len(data) == 0:
        return 0.0
    
    from collections import Counter
    import math
    
    freq = Counter(data)
    entropy = 0.0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    
    return entropy


def analyze_decryption_result(original, decrypted, name):
    """Analyze the result of decryption."""
    orig_entropy = calc_entropy(original)
    dec_entropy = calc_entropy(decrypted)
    
    print(f"\n  {name}:")
    print(f"    Original entropy:  {orig_entropy:.3f}")
    print(f"    Decrypted entropy: {dec_entropy:.3f}")
    
    # Check for common patterns in decrypted data
    # PE code typically has lower entropy than encrypted data
    
    # Look for common x86 instruction patterns
    patterns = {
        b'\x55\x8b\xec': 'push ebp; mov ebp,esp (function prologue)',
        b'\x83\xec': 'sub esp (stack allocation)',
        b'\xc3': 'ret',
        b'\xcc': 'int3 (padding)',
        b'\x8b\x45': 'mov eax,[ebp+...]',
        b'\x89\x45': 'mov [ebp+...],eax',
    }
    
    found_patterns = []
    for pattern, desc in patterns.items():
        count = decrypted.count(pattern)
        if count > 10:
            found_patterns.append(f"{desc}: {count}")
    
    if found_patterns:
        print(f"    Common x86 patterns found:")
        for p in found_patterns[:5]:
            print(f"      - {p}")
    
    # Check for null bytes (common in code)
    null_ratio = decrypted.count(b'\x00') / len(decrypted) if len(decrypted) > 0 else 0
    print(f"    Null byte ratio: {null_ratio:.2%}")
    
    return dec_entropy < orig_entropy


def decrypt_dll(input_path, output_path=None):
    """
    Attempt to decrypt the activation.x86.dll file.
    
    Args:
        input_path: Path to the encrypted DLL
        output_path: Path to write decrypted DLL (optional)
    """
    print(f"\n{'='*60}")
    print("Dead Space 2 activation.x86.dll Decryptor")
    print(f"{'='*60}\n")
    
    # Test XTEA implementation first
    if not test_xtea():
        print("XTEA implementation test failed!")
        return False
    
    # Read the file
    print(f"\nReading {input_path}...")
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    print(f"  File size: {len(data):,} bytes")
    
    # Parse PE structure
    print("\nParsing PE structure...")
    sections = parse_pe_sections(data)
    
    print("\nSections:")
    for sec in sections:
        entropy = 0
        if sec['raw_size'] > 0 and sec['raw_ptr'] + sec['raw_size'] <= len(data):
            sec_data = data[sec['raw_ptr']:sec['raw_ptr']+sec['raw_size']]
            entropy = calc_entropy(sec_data)
        
        print(f"  {sec['name']:8s} VirtAddr=0x{sec['virt_addr']:08X} "
              f"RawPtr=0x{sec['raw_ptr']:08X} RawSize=0x{sec['raw_size']:08X} "
              f"Entropy={entropy:.2f}")
    
    # Find sections to decrypt
    # Based on our analysis:
    # - .text section (encrypted, entropy ~8.0)
    # - S3 section (main packed code, entropy ~8.0)
    
    print("\n" + "="*60)
    print("Attempting Decryption")
    print("="*60)
    
    print(f"\nXTEA Key: {' '.join(f'0x{k:08X}' for k in XTEA_KEY)}")
    print(f"XTEA Delta: 0x{XTEA_DELTA:08X}")
    print(f"XTEA Rounds: {XTEA_ROUNDS}")
    
    decrypted_sections = {}
    
    for sec in sections:
        if sec['raw_size'] == 0:
            continue
        
        sec_data = bytes(data[sec['raw_ptr']:sec['raw_ptr']+sec['raw_size']])
        entropy = calc_entropy(sec_data)
        
        # Only try to decrypt high-entropy sections
        if entropy > 7.5:
            print(f"\n[*] Attempting to decrypt {sec['name']} (entropy {entropy:.2f})...")
            
            # Try decryption
            try:
                decrypted = xtea_decrypt_data(sec_data, XTEA_KEY)
                success = analyze_decryption_result(sec_data, decrypted, sec['name'])
                
                if success:
                    decrypted_sections[sec['name']] = {
                        'offset': sec['raw_ptr'],
                        'original': sec_data,
                        'decrypted': decrypted
                    }
            except Exception as e:
                print(f"    Error: {e}")
    
    # Try decrypting with different key orderings
    # Sometimes the key is stored in different order
    print("\n[*] Trying alternative key orderings...")
    
    alt_keys = [
        XTEA_KEY[::-1],  # Reversed
        [XTEA_KEY[3], XTEA_KEY[2], XTEA_KEY[1], XTEA_KEY[0]],  # Reversed order
        [XTEA_KEY[1], XTEA_KEY[0], XTEA_KEY[3], XTEA_KEY[2]],  # Swapped pairs
    ]
    
    for idx, alt_key in enumerate(alt_keys):
        print(f"\n  Alternative key {idx+1}: {' '.join(f'0x{k:08X}' for k in alt_key)}")
        
        # Test on first 1KB of S3 section
        for sec in sections:
            if sec['name'] == 'S3' and sec['raw_size'] > 0:
                test_data = bytes(data[sec['raw_ptr']:sec['raw_ptr']+1024])
                decrypted = xtea_decrypt_data(test_data, alt_key)
                dec_entropy = calc_entropy(decrypted)
                print(f"    S3 first 1KB entropy after decrypt: {dec_entropy:.2f}")
                
                # Check for PE signature or common code patterns
                if b'MZ' in decrypted[:256] or decrypted[:2] == b'\x55\x8b':
                    print(f"    [!] Found potential valid code with this key!")
    
    # Write output if requested
    if output_path and decrypted_sections:
        print(f"\n[*] Writing decrypted data to {output_path}...")
        
        output_data = bytearray(data)
        
        for name, info in decrypted_sections.items():
            offset = info['offset']
            decrypted = info['decrypted']
            output_data[offset:offset+len(decrypted)] = decrypted
            print(f"    Replaced {name} at offset 0x{offset:X}")
        
        with open(output_path, 'wb') as f:
            f.write(output_data)
        
        print(f"    Written {len(output_data):,} bytes")
    
    # Also dump individual sections for analysis
    if decrypted_sections:
        output_dir = Path(output_path).parent if output_path else Path('.')
        
        for name, info in decrypted_sections.items():
            sec_path = output_dir / f"decrypted_{name.strip('.')}.bin"
            with open(sec_path, 'wb') as f:
                f.write(info['decrypted'])
            print(f"    Dumped {name} to {sec_path}")
    
    return True


def examine_entry_point(data):
    """
    Examine the entry point code more closely to understand the decryption.
    """
    print("\n" + "="*60)
    print("Entry Point Analysis")
    print("="*60)
    
    # Entry point is at RVA 0x00109049
    # S3 section: VirtAddr=0x109000, RawPtr=0xA1A00
    entry_rva = 0x00109049
    s3_virt = 0x00109000
    s3_raw = 0x000A1A00
    
    entry_file_offset = s3_raw + (entry_rva - s3_virt)
    
    print(f"\nEntry point file offset: 0x{entry_file_offset:X}")
    
    # Read the entry point stub
    stub = data[entry_file_offset:entry_file_offset+0x200]
    
    print("\nEntry point stub (first 32 bytes):")
    for i in range(0, 32, 16):
        hex_str = ' '.join(f'{b:02x}' for b in stub[i:i+16])
        print(f"  {entry_file_offset+i:06X}: {hex_str}")
    
    # Look for the key constants being pushed
    print("\nSearching for key constant pushes...")
    
    key_patterns = [
        (b'\x68\x4a\xb3\x14\x06', "push 0x0614B34A"),
        (b'\x68\xc7\x5e\xbd\xf6', "push 0xF6BD5EC7"),
        (b'\x68\xb5\xc6\x8e\x40', "push 0x408EC6B5"),
        (b'\x68\x22\xd2\xe4\xe2', "push 0xE2E4D222"),
    ]
    
    for pattern, desc in key_patterns:
        pos = stub.find(pattern)
        if pos != -1:
            print(f"  Found {desc} at offset +0x{pos:X}")
    
    # Look for the TEA delta constant
    delta_le = struct.pack('<I', XTEA_DELTA)
    delta_pos = stub.find(delta_le)
    if delta_pos != -1:
        print(f"  Found TEA delta 0x{XTEA_DELTA:08X} at offset +0x{delta_pos:X}")
    
    # Examine the decryption size parameter
    # From disassembly: push 0x0056D087 (size)
    size_pattern = b'\x68\x87\xd0\x56\x00'
    size_pos = stub.find(size_pattern)
    if size_pos != -1:
        print(f"  Found size push 0x0056D087 at offset +0x{size_pos:X}")
        print(f"    This suggests {0x0056D087:,} bytes to decrypt")


def main():
    if len(sys.argv) < 2:
        dll_path = "/mnt/games3/SteamLibrary/steamapps/common/Dead Space 2/activation.x86.dll"
        if not os.path.exists(dll_path):
            print(f"Usage: {sys.argv[0]} <activation.x86.dll> [output.dll]")
            sys.exit(1)
    else:
        dll_path = sys.argv[1]
    
    output_path = sys.argv[2] if len(sys.argv) > 2 else "/tmp/activation_decrypted.dll"
    
    # Read file for entry point analysis
    with open(dll_path, 'rb') as f:
        data = f.read()
    
    examine_entry_point(data)
    
    # Attempt decryption
    decrypt_dll(dll_path, output_path)


if __name__ == '__main__':
    main()
