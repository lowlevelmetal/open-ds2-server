# Dead Space 2 - Technical Documentation

This directory contains detailed technical documentation from the reverse engineering of Dead Space 2 (PC, 2011).

## Document Index

| # | Document | Description |
|---|----------|-------------|
| 1 | [Solidshield Unpacking](01-solidshield-unpacking.md) | DRM protection analysis, XTEA decryption, unpacking methodology |
| 2 | [Activation DLL Analysis](02-activation-dll-analysis.md) | Complete .text section analysis of `activation.x86.dll` (188 functions) |
| 3 | [Main Executable Analysis](03-main-executable-analysis.md) | `deadspace2.exe` structure, sections, BlazeSDK, multiplayer |
| 4 | [Blaze Connection Analysis](04-blaze-connection-analysis.md) | EA server connection flow, state machine, server emulation notes |

---

## Quick Reference

### Protection Layers

| Layer | Type | Status |
|-------|------|--------|
| Layer 1 | XTEA Stream Cipher | ✅ Fully Reversed |
| Layer 2 | Metamorphic Obfuscation | ✅ Bypassed (memory dump) |
| Layer 3 | .text Encryption (EXE) | ✅ Dumped from memory |

### Key Files

| File | Size | Purpose |
|------|------|---------|
| `activation.x86.dll` | 6.1 MB | DRM activation library |
| `deadspace2.exe` | 46.2 MB | Main game executable |

### Encryption Keys

| Target | Algorithm | Key |
|--------|-----------|-----|
| activation.x86.dll (S3) | XTEA | `408ec6b5 e2e4d222 0614b34a f6bd5ec7` |
| deadspace2.exe (QuFIo) | XTEA | `0CB82F90 358B34CC 5D36466A 1D5D5714` |

### EA Server Infrastructure

| Server | Purpose |
|--------|---------|
| gosredirector.online.ea.com | Production redirector (port 42127) |
| gosredirector.stest.ea.com | Staging/test |
| demangler.ea.com | NAT traversal |

### Connection State Machine

```
DEACTIVATED → UNINITIALIZED → INITIALIZED → PROFILE_LOADED
    → NETWORK_INITIALIZED → CONNECTED → AUTHENTICATED
```

---

## Document Details

### 01 - Solidshield Unpacking

Comprehensive analysis of the Solidshield 2.x DRM protection:
- PE section analysis and entropy measurements
- XTEA decryption algorithm implementation
- Metamorphic code characteristics
- Memory dumping techniques for Wine/Proton

### 02 - Activation DLL Analysis

Complete reverse engineering of the decrypted `activation.x86.dll`:
- 188 functions documented with addresses and purposes
- Export table analysis (6 exports)
- C runtime library identification
- Activation/license validation flow

### 03 - Main Executable Analysis

Deep dive into `deadspace2.exe` structure:
- PE header and 12-section layout
- Solidshield protection flow diagram
- BlazeSDK class enumeration (453 classes)
- Multiplayer implementation details
- Error code mappings (164 codes)

### 04 - Blaze Connection Analysis

EA's BlazeSDK multiplayer connection system:
- 12-state connection state machine
- Server hostname table locations
- Authentication and GameManager components
- QoS endpoint URLs
- Server emulation requirements

---

## Related Files

| Location | Contents |
|----------|----------|
| `/scripts/` | Python tools for unpacking and analysis |
| `/dumps/` | Memory dumps and extracted sections |
| `/bin/` | Original protected binaries |

---

## Analysis Timeline

| Session | Focus | Output |
|---------|-------|--------|
| 1-5 | activation.x86.dll unpacking | Decrypted DLL |
| 6-9 | .text section analysis | Function documentation |
| 10-12 | deadspace2.exe analysis | PE structure, BlazeSDK |
| 13 | Memory dump & Blaze analysis | Connection flow |

---

*Generated through reverse engineering analysis, 2024-2026*
