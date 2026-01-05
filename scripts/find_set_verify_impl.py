#!/usr/bin/env python3
"""
Find SSL_CTX_set_verify implementation in activation.dll
The function body looks like:
    mov eax, [esp+4]   ; ctx
    mov ecx, [esp+8]   ; mode
    mov edx, [esp+12]  ; callback
    mov [eax+X], ecx   ; ctx->verify_mode = mode
    mov [eax+Y], edx   ; ctx->verify_callback = callback
    ret
"""

with open('dumps/activation_live_text.bin', 'rb') as f:
    data = f.read()

TEXT_BASE = 0x795e1000

print("Searching for SSL_CTX_set_verify implementation pattern...")
print("Looking for: get 3 args from stack, write to struct offsets, ret\n")

# Pattern: mov eax,[esp+4]; mov ecx,[esp+8]; mov edx,[esp+0xc]
for i in range(len(data) - 30):
    # Look for consecutive argument loads
    if (data[i:i+4] == bytes([0x8b, 0x44, 0x24, 0x04]) and      # mov eax, [esp+4]
        data[i+4:i+8] == bytes([0x8b, 0x4c, 0x24, 0x08])):      # mov ecx, [esp+8]
        # Check if third arg is loaded nearby
        for j in range(4, 12):
            if data[i+4+j:i+4+j+4] == bytes([0x8b, 0x54, 0x24, 0x0c]):  # mov edx, [esp+0xc]
                # Check for ret nearby
                for k in range(10, 30):
                    if data[i+4+j+4+k] == 0xc3:  # ret
                        print(f"Candidate at 0x{TEXT_BASE + i:08x}")
                        # Show surrounding bytes
                        print(f"  Bytes: {data[i:i+30].hex()}")
                        break
                break

# Also search for the simpler pattern without explicit loads (args already in regs)
# mov [eax+X], ecx; mov [eax+Y], edx; ret
print("\nSearching for simple dual-write pattern...")
for i in range(len(data) - 20):
    # mov [eax+X], ecx; mov [eax+Y], edx; ret (where Y = X+4)
    for x in range(0x50, 0xa0, 4):
        if (data[i:i+3] == bytes([0x89, 0x48, x]) and           # mov [eax+x], ecx
            data[i+3:i+6] == bytes([0x89, 0x50, x+4]) and       # mov [eax+x+4], edx
            data[i+6] == 0xc3):                                  # ret
            print(f"  Found at 0x{TEXT_BASE + i:08x}: writes to offsets 0x{x:02x}, 0x{x+4:02x}")

# Look for function that reads 3 args and does two writes
print("\nSearching for 3-arg function with two struct writes...")
for i in range(len(data) - 50):
    # Function prologue or direct arg access
    if data[i:i+4] == bytes([0x8b, 0x44, 0x24, 0x04]):  # mov eax, [esp+4]
        # Look for two writes to the same base pointer
        writes = []
        for j in range(4, 40):
            if i+j+3 <= len(data):
                # mov [eax+X], reg
                if data[i+j] == 0x89 and data[i+j+1] in [0x48, 0x50, 0x58, 0x70, 0x78]:
                    offset = data[i+j+2]
                    reg = {0x48: 'ecx', 0x50: 'edx', 0x58: 'ebx', 0x70: 'esi', 0x78: 'edi'}[data[i+j+1]]
                    writes.append((j, offset, reg))
        # Check for ret at end
        for j in range(10, 50):
            if i+j < len(data) and data[i+j] == 0xc3:
                if len(writes) == 2 and writes[1][1] == writes[0][1] + 4:
                    print(f"  0x{TEXT_BASE + i:08x}: writes offset 0x{writes[0][1]:02x} ({writes[0][2]}), 0x{writes[1][1]:02x} ({writes[1][2]})")
                    print(f"    Bytes: {data[i:i+j+1].hex()}")
                break

