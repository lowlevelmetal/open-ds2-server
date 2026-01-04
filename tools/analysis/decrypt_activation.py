#!/usr/bin/env python3
"""
Dead Space 2 activation.x86.dll Decryptor

This script decrypts the packed activation.x86.dll using the XTEA-XOR algorithm
discovered through reverse engineering.

FINDINGS:
=========
The packer uses a custom XTEA-based stream cipher:
1. Entry stub at S3+0x49 (file offset 0xA1A49)
2. XTEA key pushed: 0x0614B34A, 0xF6BD5EC7, 0x408EC6B5, 0xE2E4D222
3. After stack setup, key array becomes:
   k[0] = 0x408EC6B5
   k[1] = 0xE2E4D222
   k[2] = 0x0614B34A
   k[3] = 0xF6BD5EC7
4. Counter initialized: v0=0, v1=0
5. Algorithm: XOR encrypted data with XTEA-encrypted counter (OFB mode)

CHALLENGE:
==========
The dumped binary and packed binary show different keystreams were used
for different sections. The exact counter/key relationship needs more
reverse engineering to fully understand.

This script attempts to decrypt using the known algorithm and compares
with the known-good memory dump.
"""

import struct
import sys
import os
from pathlib import Path
from collections import Counter
import math

# XTEA Constants  
XTEA_DELTA = 0x9E3779B9
XTEA_ROUNDS = 32

# Key orderings we've found
KEY_PUSH_ORDER = [0x0614B34A, 0xF6BD5EC7, 0x408EC6B5, 0xE2E4D222]
KEY_STACK_ORDER = [0xE2E4D222, 0x408EC6B5, 0xF6BD5EC7, 0x0614B34A]
KEY_DERIVED = [0x408EC6B5, 0xE2E4D222, 0x0614B34A, 0xF6BD5EC7]


def xtea_encrypt_block(v0, v1, key):
    """XTEA encrypt a single 64-bit block."""
    sum_val = 0
    for _ in range(XTEA_ROUNDS):
        v0 = (v0 + ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + key[sum_val & 3]))) & 0xFFFFFFFF
        sum_val = (sum_val + XTEA_DELTA) & 0xFFFFFFFF
        v1 = (v1 + ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + key[(sum_val >> 11) & 3]))) & 0xFFFFFFFF
    return v0, v1


def xtea_decrypt_block(v0, v1, key):
    """XTEA decrypt a single 64-bit block."""
    sum_val = (XTEA_DELTA * XTEA_ROUNDS) & 0xFFFFFFFF
    for _ in range(XTEA_ROUNDS):
        v1 = (v1 - ((((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum_val + key[(sum_val >> 11) & 3]))) & 0xFFFFFFFF
        sum_val = (sum_val - XTEA_DELTA) & 0xFFFFFFFF
        v0 = (v0 - ((((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum_val + key[sum_val & 3]))) & 0xFFFFFFFF
    return v0, v1


def entropy(data):
    """Calculate Shannon entropy."""
    if not data:
        return 0.0
    freq = Counter(data)
    return -sum((c/len(data)) * math.log2(c/len(data)) for c in freq.values())


def parse_pe_sections(data):
    """Parse PE section headers."""
    if data[:2] != b'MZ':
        raise ValueError("Not a valid PE file")
    
    e_lfanew = struct.unpack('<I', data[0x3c:0x40])[0]
    coff_offset = e_lfanew + 4
    num_sections = struct.unpack('<H', data[coff_offset+2:coff_offset+4])[0]
    opt_size = struct.unpack('<H', data[coff_offset+16:coff_offset+18])[0]
    section_offset = coff_offset + 20 + opt_size
    
    sections = []
    for i in range(num_sections):
        s = section_offset + i * 40
        name = data[s:s+8].rstrip(b'\x00').decode('ascii', errors='replace')
        virt_size = struct.unpack('<I', data[s+8:s+12])[0]
        virt_addr = struct.unpack('<I', data[s+12:s+16])[0]
        raw_size = struct.unpack('<I', data[s+16:s+20])[0]
        raw_ptr = struct.unpack('<I', data[s+20:s+24])[0]
        sections.append({
            'name': name,
            'virt_addr': virt_addr,
            'virt_size': virt_size,
            'raw_ptr': raw_ptr,
            'raw_size': raw_size
        })
    return sections


def find_keystream_by_known_plaintext(packed_path, unpacked_path, offset, size=64):
    """Calculate keystream by XORing packed with unpacked data."""
    with open(packed_path, 'rb') as f:
        packed = f.read()
    with open(unpacked_path, 'rb') as f:
        unpacked = f.read()
    
    # Get sections to map offsets
    packed_secs = parse_pe_sections(packed)
    
    # For packed file, use raw_ptr offset
    # For unpacked (memory dump), use virtual address offset
    packed_data = packed[offset:offset+size]
    
    # Find which section this is in
    for sec in packed_secs:
        if sec['raw_ptr'] <= offset < sec['raw_ptr'] + sec['raw_size']:
            # Calculate VA for this offset
            file_offset_in_sec = offset - sec['raw_ptr']
            va = sec['virt_addr'] + file_offset_in_sec
            print(f"  Section: {sec['name']}, VA: 0x{va:X}")
            break
    else:
        va = offset  # Fallback
    
    unpacked_data = unpacked[va:va+size]
    
    keystream = []
    for i in range(0, min(len(packed_data), len(unpacked_data)), 8):
        enc_block = packed_data[i:i+8]
        dec_block = unpacked_data[i:i+8]
        
        if len(enc_block) < 8 or len(dec_block) < 8:
            break
            
        enc_v0 = struct.unpack('<I', enc_block[0:4])[0]
        enc_v1 = struct.unpack('<I', enc_block[4:8])[0]
        dec_v0 = struct.unpack('<I', dec_block[0:4])[0]
        dec_v1 = struct.unpack('<I', dec_block[4:8])[0]
        
        ks0 = enc_v0 ^ dec_v0
        ks1 = enc_v1 ^ dec_v1
        keystream.append((ks0, ks1))
    
    return keystream


def try_find_counter_for_keystream(target_ks0, target_ks1, key, max_search=10000):
    """Try to find counter values that produce the target keystream."""
    for v0 in range(max_search):
        for v1 in range(max_search):
            ks0, ks1 = xtea_encrypt_block(v0, v1, key)
            if ks0 == target_ks0 and ks1 == target_ks1:
                return v0, v1
    return None, None


def decrypt_with_keystream(encrypted_data, keystream_func):
    """Decrypt data using a keystream generator function."""
    result = bytearray()
    for i in range(0, len(encrypted_data), 8):
        block = encrypted_data[i:i+8]
        if len(block) < 8:
            block = block + b'\x00' * (8 - len(block))
        
        ks0, ks1 = keystream_func(i // 8)
        
        enc_v0 = struct.unpack('<I', block[0:4])[0]
        enc_v1 = struct.unpack('<I', block[4:8])[0]
        
        dec_v0 = enc_v0 ^ ks0
        dec_v1 = enc_v1 ^ ks1
        
        result.extend(struct.pack('<II', dec_v0, dec_v1))
    
    return bytes(result[:len(encrypted_data)])


def analyze_binary(packed_path, unpacked_path):
    """Analyze the encryption by comparing packed and unpacked binaries."""
    
    print("Dead Space 2 activation.x86.dll Decryption Analysis")
    print("=" * 60)
    
    with open(packed_path, 'rb') as f:
        packed = f.read()
    
    with open(unpacked_path, 'rb') as f:
        unpacked = f.read()
    
    print(f"\nPacked size:   {len(packed):,} bytes")
    print(f"Unpacked size: {len(unpacked):,} bytes")
    
    # Parse sections
    packed_secs = parse_pe_sections(packed)
    
    print("\n" + "=" * 60)
    print("Section Analysis")
    print("=" * 60)
    
    for sec in packed_secs:
        if sec['raw_size'] == 0:
            continue
        
        packed_data = packed[sec['raw_ptr']:sec['raw_ptr']+sec['raw_size']]
        packed_entropy = entropy(packed_data)
        
        # Get corresponding unpacked data (at VA offset for memory dump)
        if sec['virt_addr'] + sec['raw_size'] <= len(unpacked):
            unpacked_data = unpacked[sec['virt_addr']:sec['virt_addr']+sec['raw_size']]
            unpacked_entropy = entropy(unpacked_data)
        else:
            unpacked_data = b''
            unpacked_entropy = 0
        
        print(f"\n{sec['name']}:")
        print(f"  VA: 0x{sec['virt_addr']:08X}, Raw: 0x{sec['raw_ptr']:08X}, Size: 0x{sec['raw_size']:X}")
        print(f"  Packed entropy:   {packed_entropy:.3f}")
        print(f"  Unpacked entropy: {unpacked_entropy:.3f}")
        
        # Check if encrypted (high entropy in packed, lower in unpacked)
        if packed_entropy > 7.5 and unpacked_entropy < packed_entropy:
            print(f"  STATUS: ENCRYPTED (entropy drop: {packed_entropy - unpacked_entropy:.2f})")
            
            # Calculate keystream for first few blocks
            print(f"  Keystream analysis:")
            ks = find_keystream_by_known_plaintext(
                packed_path, unpacked_path, 
                sec['raw_ptr'], 64
            )
            for i, (ks0, ks1) in enumerate(ks[:4]):
                print(f"    Block {i}: 0x{ks0:08X} 0x{ks1:08X}")
        elif packed_entropy > 7.5:
            print(f"  STATUS: HIGH ENTROPY (possibly compressed or encrypted)")
        else:
            print(f"  STATUS: UNENCRYPTED")
    
    # Analyze the XTEA algorithm
    print("\n" + "=" * 60)
    print("XTEA Key Analysis")
    print("=" * 60)
    
    print(f"\nKeys found in entry stub:")
    print(f"  Push order: {[hex(k) for k in KEY_PUSH_ORDER]}")
    print(f"  Stack order: {[hex(k) for k in KEY_STACK_ORDER]}")
    print(f"  Derived: {[hex(k) for k in KEY_DERIVED]}")
    
    # Test which key produces matching keystream
    text_ks = find_keystream_by_known_plaintext(packed_path, unpacked_path, 0x400, 8)
    if text_ks:
        target_ks0, target_ks1 = text_ks[0]
        print(f"\n.text first keystream block: 0x{target_ks0:08X} 0x{target_ks1:08X}")
        
        print("\nTesting keys with counter (0,0):")
        for name, key in [("Push order", KEY_PUSH_ORDER), 
                          ("Stack order", KEY_STACK_ORDER),
                          ("Derived", KEY_DERIVED)]:
            ks0, ks1 = xtea_encrypt_block(0, 0, key)
            match = "MATCH!" if (ks0 == target_ks0 and ks1 == target_ks1) else ""
            print(f"  {name}: 0x{ks0:08X} 0x{ks1:08X} {match}")
        
        # Try to find the counter that produces this keystream
        print("\nSearching for counter values...")
        for name, key in [("Push order", KEY_PUSH_ORDER), 
                          ("Stack order", KEY_STACK_ORDER),
                          ("Derived", KEY_DERIVED)]:
            v0, v1 = try_find_counter_for_keystream(target_ks0, target_ks1, key, 1000)
            if v0 is not None:
                print(f"  {name}: Found counter v0={v0}, v1={v1}")


def main():
    packed_path = "/mnt/games3/SteamLibrary/steamapps/common/Dead Space 2/activation.x86.dll"
    unpacked_path = "/home/okole/Work/personal/open-ds2-server/tools/activation_dumped.bin"
    
    if len(sys.argv) > 1:
        packed_path = sys.argv[1]
    if len(sys.argv) > 2:
        unpacked_path = sys.argv[2]
    
    if not os.path.exists(packed_path):
        print(f"Error: Packed file not found: {packed_path}")
        sys.exit(1)
    
    if not os.path.exists(unpacked_path):
        print(f"Error: Unpacked file not found: {unpacked_path}")
        print("Please run the game and dump the unpacked DLL first")
        sys.exit(1)
    
    analyze_binary(packed_path, unpacked_path)


if __name__ == '__main__':
    main()
