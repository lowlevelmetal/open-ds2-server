# Dead Space 2 Main Executable Analysis

## Document Information
- **Target**: `bin/deadspace2.exe`
- **Analysis Date**: January 4-5, 2026
- **Analyst**: Reverse Engineering Sessions 10, 11, 12
- **Related**: [REVERSE_ENGINEERING_NOTES.md](REVERSE_ENGINEERING_NOTES.md) (Sessions 10-12)

---

## Executive Summary

Dead Space 2's main executable is a 46 MB PE32 binary protected by **Solidshield 2.0.3.1** DRM. The .text section containing all game code is **fully encrypted** (entropy 8.00). The executable contains embedded **BlazeSDK** for EA's online multiplayer services, with hardcoded EA server hostnames.

### Key Findings (Updated Session 12)

| Finding | Details |
|---------|---------|
| **Multiplayer Location** | Embedded in main EXE, NOT a separate DLL |
| **DRM Link** | Imports `start` from `activation.x86.dll` |
| **XTEA Key** | `0CB82F90358B34CC5D36466A1D5D5714` |
| **Blaze Classes** | 453 classes across 10 namespaces |
| **Error Codes** | 164 total (SDK: 26, AUTH: 76, GM: 62) |
| **Imports** | 22 DLLs visible pre-decryption |
| **Analysis Limit** | .text encrypted - memory dump required |

---

## File Properties

| Property | Value |
|----------|-------|
| **Filename** | deadspace2.exe |
| **Size** | 48,444,416 bytes (46.2 MB) |
| **Format** | PE32 executable (GUI) |
| **Architecture** | Intel i386 (32-bit) |
| **Sections** | 12 |
| **Entry Point** | 0x0282D049 (QuFIo section) |
| **Image Base** | 0x00400000 |
| **Linker** | Microsoft Visual C++ 9.0 |
| **Build Date** | December 14, 2010 00:08:54 |
| **Build Type** | Win D3D Final |

### Identification Strings

```
Internal ID:     CLIENT.Ph.Visceral_EA-RedwoodShores_DeadSpace2_Xbox360-PS3_Win32PC
Build Config:    deadspace-2011-pc
Asset Path:      /PC/DEADSPACE-2011
PDB Path:        c:\builds\packages\deadspace\dev\exe\Win D3D Final\deadspace_f.pdb
Protection:      Solidshield 2.0.3.1 (2011/01/13)
```

---

## PE Structure

### Section Table

| # | Name | Virtual Addr | Virtual Size | Raw Size | Raw Ptr | Entropy | Characteristics |
|---|------|--------------|--------------|----------|---------|---------|-----------------|
| 0 | .text | 0x00401000 | 0x016A0000 (23.5 MB) | 0x0169F800 | 0x00000400 | **8.00** | CODE, EXEC, READ |
| 1 | .rdata | 0x01AA1000 | 0x0018F000 (1.6 MB) | 0x0018E400 | 0x0169FC00 | 6.17 | DATA, READ |
| 2 | .data | 0x01C30000 | 0x00528000 (5.3 MB) | 0x003EC200 | 0x0182E000 | 4.27 | DATA, R/W |
| 3 | .idata | 0x01D58000 | 0x00003000 | 0x00002A00 | 0x01C1A200 | - | DATA, R/W |
| 4 | .tls | 0x01D5B000 | 0x00001000 | 0x00000400 | 0x01C1CC00 | - | DATA, R/W |
| 5 | .rsrc | 0x01D5C000 | 0x00006000 | 0x00005800 | 0x01C1D000 | - | DATA, READ |
| 6 | .reloc | 0x01D62000 | 0x00263000 (2.5 MB) | 0x00262600 | 0x01C22800 | - | DATA, READ |
| 7 | .bind | 0x01FC5000 | 0x00058000 (352 KB) | 0x00058000 | 0x01E84E00 | **8.00** | CODE+DATA, EXEC, READ |
| 8 | ri | 0x0201D000 | 0x00010000 (64 KB) | 0x00000000 | 0x00000000 | - | UNINIT, R/W |
| 9 | aYv | 0x0202D000 | 0x00400000 (4 MB) | 0x00000000 | 0x00000000 | - | CODE+UNINIT, EXEC, R/W |
| 10 | QuFIo | 0x0282D000 | 0x00F23000 (15.1 MB) | 0x00F23000 | 0x01EDCE00 | **8.00** | CODE, EXEC, READ |
| 11 | sr | 0x03750000 | 0x00034000 (208 KB) | 0x00033600 | 0x02DFFE00 | 5.96 | DATA, READ |

### Section Analysis

#### Encrypted Sections (Entropy = 8.00)

| Section | Size | Purpose |
|---------|------|---------|
| **.text** | 23.5 MB | Main game code - FULLY ENCRYPTED |
| **.bind** | 352 KB | Binding/import data - ENCRYPTED |
| **QuFIo** | 15.1 MB | Solidshield unpacker engine |

#### Clear Sections

| Section | Size | Contents |
|---------|------|----------|
| **.rdata** | 1.6 MB | String constants, RTTI, documentation |
| **.data** | 5.3 MB | Initialized game data |
| **sr** | 208 KB | Import stubs, relocations |

#### Runtime Sections (RawSize = 0)

| Section | Size | Purpose |
|---------|------|---------|
| **ri** | 64 KB | Runtime buffer |
| **aYv** | 4 MB | Decrypted code target (likely) |

---

## Solidshield Protection

### Protection Version
```
Solidshield 2.0.3.1 (2011/01/13)
```

### Protection Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    SOLIDSHIELD PROTECTION FLOW                    │
├──────────────────────────────────────────────────────────────────┤
│                                                                   │
│  Windows Loader                                                   │
│       │                                                           │
│       ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ Entry Point: 0x0282D049 (QuFIo section)                     │ │
│  │ pushfd; push eax,ecx,edx,ebx,esp,ebp,esi,edi                │ │
│  │ call $+5; pop esi (get EIP)                                 │ │
│  │ Calculate base address                                       │ │
│  └─────────────────────────────────────────────────────────────┘ │
│       │                                                           │
│       ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ LAYER 1: XTEA Stream Cipher Decryption                      │ │
│  │ Key: 0CB82F90358B34CC5D36466A1D5D5714                       │ │
│  │ Delta: 0x9E3779B9 (standard XTEA)                           │ │
│  │ Decrypts: QuFIo section internal code                       │ │
│  └─────────────────────────────────────────────────────────────┘ │
│       │                                                           │
│       ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ LAYER 2: Metamorphic Deobfuscation Engine                   │ │
│  │ • Control flow obfuscation (spaghetti code)                 │ │
│  │ • Opaque predicates                                         │ │
│  │ • Junk code insertion                                       │ │
│  │ • Anti-debug: rdtsc, cpuid timing checks                    │ │
│  │ • SEH manipulation                                          │ │
│  └─────────────────────────────────────────────────────────────┘ │
│       │                                                           │
│       ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ LAYER 3: Section Decryption                                 │ │
│  │ • Decrypts .text section (23.5 MB)                          │ │
│  │ • Possibly copies to aYv section                            │ │
│  │ • Fixes relocations                                         │ │
│  │ • Resolves real imports                                     │ │
│  └─────────────────────────────────────────────────────────────┘ │
│       │                                                           │
│       ▼                                                           │
│  ┌─────────────────────────────────────────────────────────────┐ │
│  │ Original Entry Point (OEP)                                  │ │
│  │ Location: Unknown (in decrypted .text)                      │ │
│  │ → Game initialization begins                                │ │
│  └─────────────────────────────────────────────────────────────┘ │
│                                                                   │
└──────────────────────────────────────────────────────────────────┘
```

### XTEA Key (Layer 1)

Found at QuFIo section header (file offset 0x1EDCE28):
```
0CB82F90358B34CC5D36466A1D5D5714
```

Parsed as 4 x 32-bit words (little-endian):
```c
uint32_t key[4] = {
    0x902FB80C,  // or big-endian: 0x0CB82F90
    0xCC348B35,  // interpretation depends on
    0x6A46365D,  // actual XTEA implementation
    0x14575D1D
};
```

---

## Import Analysis

> **Updated**: Session 12 - radare2 deep analysis with offsets

### Complete Import Table (22 DLLs)

| DLL | Function | Purpose |
|-----|----------|---------|
| DSOUND.dll | DirectSoundCreate (ord 1) | Audio |
| WS2_32.dll | recvfrom (ord 17) | Network recv |
| WINMM.dll | waveInReset | Audio input |
| KERNEL32.dll | CompareStringW | String compare |
| USER32.dll | MessageBoxA | Error dialogs |
| GDI32.dll | GetStockObject | Graphics |
| ADVAPI32.dll | RegSetValueExW | Registry |
| SHELL32.dll | SHGetFolderPathAndSubDirW | Paths |
| ole32.dll | CoInitialize | COM |
| OLEAUT32.dll | SysStringLen (ord 6) | COM strings |
| VERSION.dll | GetFileVersionInfoA | Version info |
| IMM32.dll | ImmDisableIME | Input method |
| DINPUT8.dll | DirectInput8Create | Input |
| d3d9.dll | Direct3DCreate9 | Direct3D |
| d3dx9_43.dll | D3DXGetShaderConstantTable | D3DX |
| IPHLPAPI.DLL | GetAdaptersAddresses | Network adapters |
| XINPUT1_3.dll | (ord 4) | Xbox controller |
| kernel32.dll | VirtualProtect, LoadLibraryA, GetProcAddress, GetModuleHandleA | Runtime |
| **activation.x86.dll** | **start** | **DRM activation** |

### Key Finding: DRM Integration

The game **directly imports** the `start` function from `activation.x86.dll`:

```
Import: activation.x86.dll!start
Purpose: DRM validation entry point
Link: Connects to analyzed activation DLL (see Sessions 1-9)
```

This confirms the DRM activation happens early in the game's initialization sequence.

### Expected Additional Imports (Runtime-Resolved)

Based on .rdata strings, the game resolves additional imports at runtime:

| DLL | Purpose |
|-----|---------|
| d3d9.dll | Direct3D 9 rendering (extended) |
| d3dx9_43.dll | D3DX helper functions (extended) |
| ntdll.dll | Native API (anti-tamper) |
| ws2_32.dll | Extended Winsock (Blaze) |

---

## Embedded Middleware

### Confirmed Libraries

| Library | Version | Purpose | Evidence |
|---------|---------|---------|----------|
| **Solidshield** | 2.0.3.1 | DRM/Copy protection | Version string |
| **BlazeSDK** | Unknown | EA Online services | Class names, strings |
| **RwAudioCore** | Unknown | EA Audio middleware | Extensive documentation strings |
| **Havok Physics** | Unknown | Physics simulation | hkp* class names |
| **DirectX 9** | June 2010 | Rendering | d3d9.dll, d3dx9_43.dll |

### RwAudioCore (EA Audio)

Extensive embedded documentation (~100KB of help text) reveals:
- Multi-platform audio engine (PC, Xbox 360, PS3, Wii)
- Supports streaming, 3D positioning, reverb, time stretching
- Plugin architecture (SndPlayer1, Pan3D, ReverbIR1, etc.)
- 7.1 surround sound support

### Havok Physics

Class names found:
```
hkpWorld
hkpEntity
hkpMotion
hkpVehicleEngine
hkpVehicleDefaultEngine
hkpContactMgrFactory
hkpSimpleConstraintContactMgr
hkpAabbPhantom
hkpKeyframedRigidMotion
```

---

## EA Online Services (BlazeSDK)

### Server Hostnames

| Hostname | Environment | Purpose |
|----------|-------------|---------|
| `gosredirector.online.ea.com` | Production | Main redirector service |
| `gosredirector.ea.com` | Production | Alternate redirector |
| `gosredirector.stest.ea.com` | Staging | Test environment |
| `gosredirector.scert.ea.com` | Secure | Certificate services |
| `demangler.ea.com` | Production | Name demangling |
| `peach.online.ea.com` | Production | Unknown service |

### QoS (Quality of Service) Endpoints

```
http://%s:%u/qos/qos?vers=%d
http://%s:%u/qos/firetype?vers=%d
http://%s:%u/qos/firewall?vers=%d
```

These endpoints determine:
- Network latency/quality
- Firewall/NAT type detection
- Connection capability

### Blaze Components

#### Core Classes
```cpp
BlazeSDK
BlazeHub::mLoginManagers
BlazeObjectType
BlazeObjectId
```

#### Game Manager
```cpp
Blaze::GameManager::CreateGameResponse
Blaze::GameManager::JoinGameResponse
Blaze::GameManager::DestroyGameRequest
Blaze::GameManager::UpdateGameSessionRequest
Blaze::GameManager::HostInfo
Blaze::GameManager::TeamCapacity
Blaze::GameManager::SetNetworkQosRequest
```

#### Matchmaking
```cpp
Blaze::GameManager::MatchmakingCustomCriteriaData
Blaze::GameManager::MatchmakingCustomAsyncStatus
GMAPI::MatchmakingPool
startMatchmaking
cancelMatchmaking
getMatchmakingConfig
```

#### User Session
```cpp
Blaze::UserSessionDisconnectReason
Blaze::UpdateUserSessionAttributeRequest
Blaze::UserSessionExtendedData
```

---

## Multiplayer Implementation

### Spawn System

```cpp
// Spawn point management
MultiplayerSpawnPoint
MPSpawnPointSelector
m_validForInitialSpawn
m_validForRespawn

// RPC Events
RPCEV_MPSpawnPointSelector_RPC_SpawnDelayResponse
RPCEV_MPSpawnPointSelector_RPC_SpawnPointResponse
RPCEV_MPSpawnPointSelector_RPC_RequestInitialSpawnPoint
RPCEV_MPSpawnPointSelector_RPC_QueueForRespawn
```

### Game Session States

```cpp
// Session lifecycle
SESSION_ERROR_GAME_SETUP_FAILED
SESSION_TERMINATED
SESSION_CANCELED
SESSION_TIMED_OUT

// Player states
PLAYER_JOIN_FROM_QUEUE_FAILED
PLAYER_JOIN_TIMEOUT
SYS_GAME_ENDING
GAME_ENDED

// Notifications
NotifyGameCreated
NotifyGameRemoved
NotifyPlayerJoinCompleted
NotifyPlayerRemoved
NotifyHostMigrationStart
NotifyHostMigrationFinished
NotifyGameStateChange
NotifyGameSettingsChange
```

### Matchmaking Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                     MATCHMAKING FLOW                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Player                                                          │
│    │                                                             │
│    ├──► startMatchmaking()                                       │
│    │         │                                                   │
│    │         ▼                                                   │
│    │    ┌─────────────────────────────────────┐                 │
│    │    │ gosredirector.online.ea.com         │                 │
│    │    │ → Blaze Matchmaking Service         │                 │
│    │    └─────────────────────────────────────┘                 │
│    │         │                                                   │
│    │         ├──► NotifyMatchmakingAsyncStatus                  │
│    │         │    (searching for players...)                     │
│    │         │                                                   │
│    │         ├──► Match Found                                    │
│    │         │    JOIN_BY_MATCHMAKING                           │
│    │         │                                                   │
│    │         ▼                                                   │
│    │    ┌─────────────────────────────────────┐                 │
│    │    │ Game Session Created                │                 │
│    │    │ NotifyGameCreated                   │                 │
│    │    │ NotifyPlayerJoinCompleted           │                 │
│    │    └─────────────────────────────────────┘                 │
│    │         │                                                   │
│    │         ▼                                                   │
│    │    Game in Progress...                                      │
│    │         │                                                   │
│    │         ▼                                                   │
│    │    GAME_ENDED / SESSION_TERMINATED                         │
│    │                                                             │
│    ├──► cancelMatchmaking() (if cancelled)                      │
│         NotifyMatchmakingFailed                                  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Team Management

```cpp
// Team operations
changeGameTeamId
setPlayerTeam
Game::CreateGameParams.mTeamCapacities

// Team errors
GAMEMANAGER_ERR_TEAMS_DISABLED
GAMEMANAGER_ERR_INVALID_TEAM_CAPACITY
GAMEMANAGER_ERR_TEAM_FULL
GAMEMANAGER_ERR_INVALID_TEAM_ID_IN_TEAM_CAPACITIES_VECTOR
GAMEMANAGER_ERR_TEAM_NOT_ALLOWED
GAMEMANAGER_ERR_TOTAL_TEAM_CAPACITY_INVALID
GAMEMANAGER_ERR_DUPLICATE_TEAM_CAPACITY
GAMEMANAGER_ERR_INVALID_TEAM_CAPACITIES_VECTOR_SIZE

// Notifications
NotifyPlayerTeamChange
NotifyGameTeamIdChange
```

### Authentication

```cpp
// Auth states
AUTHENTICATED
AUTHENTICATE_TRANSITION

// User identifiers
ACCOUNT_ID
PERSONA_NAME

// Session management
DUPLICATE_LOGIN
USER_ERR_INVALID_SESSION_INSTANCE
USER_ERR_DUPLICATE_SESSION
USER_ERR_SESSION_NOT_FOUND
```

### Network Errors

```cpp
// Connection errors
BLAZESERVER_CONN_LOST

// Matchmaking errors
GAMEMANAGER_ERR_NOT_MATCHMAKING_SESSION_OWNER
GAMEMANAGER_ERR_MATCHMAKING_NO_JOINABLE_GAMES
GAMEMANAGER_ERR_MATCHMAKING_USERSESSION_NOT_FOUND
GAMEMANAGER_ERR_UNKNOWN_MATCHMAKING_SESSION_ID
GAMEMANAGER_ERR_INVALID_MATCHMAKING_CRITERIA
```

---

## Multiplayer Server Connection Analysis

> **Reference**: See [REVERSE_ENGINEERING_NOTES.md](REVERSE_ENGINEERING_NOTES.md) Session 11 for complete analysis details.

### Connection Architecture

Dead Space 2 uses **EA's BlazeSDK** with the **DirtySock** networking library for multiplayer.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    MULTIPLAYER CONNECTION ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  ┌─────────────────┐                                                        │
│  │  deadspace2.exe │                                                        │
│  │  (Game Client)  │                                                        │
│  └────────┬────────┘                                                        │
│           │                                                                  │
│           ▼                                                                  │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐       │
│  │   DirtySock     │────▶│   ProtoHTTP     │────▶│   ProtoTunnel   │       │
│  │   (Network)     │     │   (HTTP/HTTPS)  │     │   (Game Data)   │       │
│  └────────┬────────┘     └─────────────────┘     └─────────────────┘       │
│           │                                                                  │
│           ▼                                                                  │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                         BlazeSDK Components                          │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │   │
│  │  │ BlazeHub     │  │ LoginManager │  │ GameManager  │               │   │
│  │  │ (Central)    │  │ (Auth)       │  │ (Sessions)   │               │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘               │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐               │   │
│  │  │ Redirector   │  │ Playgroups   │  │ Matchmaking  │               │   │
│  │  │ (Routing)    │  │ (Parties)    │  │ (Queues)     │               │   │
│  │  └──────────────┘  └──────────────┘  └──────────────┘               │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Connection Trigger Points

The game initiates server connections at **two distinct points**:

#### Trigger 1: Title Screen ("Press Any Button")

| Aspect | Detail |
|--------|--------|
| **When** | After game logo/intro, before main menu |
| **Purpose** | Background initialization of online services |
| **Operations** | DirtySock init, Redirector connection, QoS/NAT detection |
| **Authentication** | NOT required at this stage |

**UI Strings**:
- `$ui_nu00_connectingTitle_mc` - "Connecting..."
- `$ui_gpop_NoConnection` - No connection popup
- `$ui_gpop_NoConnectionMessage_mc` - Connection error message

#### Trigger 2: Multiplayer Menu Selection

| Aspect | Detail |
|--------|--------|
| **When** | User selects "Multiplayer" from main menu |
| **Purpose** | Full authentication and session initialization |
| **Operations** | EA Account login, Online Pass check, session setup |
| **Authentication** | REQUIRED |

**UI Strings**:
- `$ui_gpop_loginFailedTitle_mc` - Login failed
- `$ui_gpop_personaLoginFailedMessage_mc` - Persona login error
- `$ui_redeemCodeDescriptionOnlinePass` - Online Pass prompt

### Connection State Machine

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    CONNECTION STATE MACHINE                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  [DISCONNECTED] ──────────────────────────────────────────────┐             │
│        │                                                       │             │
│        │ Initialize                                            │             │
│        ▼                                                       │             │
│  [NETWORK_INITIALIZE_TRANSITION]                               │             │
│        │                                                       │             │
│        ├── Success ──▶ [NETWORK_INITIALIZED]                   │             │
│        │                      │                                │             │
│        │                      │ Connect to Redirector          │             │
│        │                      ▼                                │             │
│        │               [CONNECT_TRANSITION]                    │             │
│        │                      │                                │             │
│        │                      ├── Success ──▶ [CONNECTED]      │             │
│        │                      │                    │           │             │
│        │                      │                    │ Authenticate            │
│        │                      │                    ▼           │             │
│        │                      │        [AUTHENTICATE_TRANSITION]│            │
│        │                      │                    │           │             │
│        │                      │                    ├── Success │             │
│        │                      │                    │     ▼     │             │
│        │                      │                    │ [AUTHENTICATED]         │
│        │                      │                    │     │     │             │
│        │                      │                    │     ▼     │             │
│        │                      │                    │ [ACTIVE_CONNECTED]      │
│        │                      │                    │           │             │
│        │                      │                    │           │             │
│        │                      │                    │◀──────────┤             │
│        │                      │                    │           │             │
│        │                      ├── Failure ─────────┼───────────┤             │
│        │                                           │           │             │
│        ├── Failure ────────────────────────────────┼───────────┤             │
│        │                                           │           │             │
│        ▼                                           ▼           │             │
│  [ERR_CANNOT_INIT_NETWORK]              [ERR_CONNECTION_FAILED]│             │
│        │                                           │           │             │
│        └───────────────────────────────────────────┴───────────┘             │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Step-by-Step Connection Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│            DEAD SPACE 2 MULTIPLAYER CONNECTION FLOW                          │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  GAME LAUNCH                                                                 │
│      │                                                                       │
│      ▼                                                                       │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 1: DirtySock Initialization                                     │   │
│  │   • Initialize network stack                                          │   │
│  │   • Setup ProtoHTTP, ProtoTunnel                                     │   │
│  │   ✗ EARLY EXIT: SDK_ERR_DIRTYSOCK_UNINITIALIZED                      │   │
│  └────────────────────────────────┬─────────────────────────────────────┘   │
│                                   │                                          │
│                                   ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 2: Redirector Connection                                        │   │
│  │   • Connect to gosredirector.online.ea.com                           │   │
│  │   • Request: getServerInstance                                        │   │
│  │   • Response: ServerInstanceInfo (actual game server)                │   │
│  │   ✗ EARLY EXIT: ERR_CONNECTION_FAILED, SDK_ERR_RPC_TIMEOUT           │   │
│  └────────────────────────────────┬─────────────────────────────────────┘   │
│                                   │                                          │
│                                   ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 3: QoS & NAT Detection                                          │   │
│  │   • fetchQosConfig()                                                  │   │
│  │   • HTTP GET: /qos/qos, /qos/firetype, /qos/firewall                 │   │
│  │   • Determine NAT_TYPE_*                                              │   │
│  │   ✗ EARLY EXIT: SDK_ERR_QOS_PINGSITE_NOT_INITIALIZED                 │   │
│  │   ⚠ WARNING: NAT_TYPE_STRICT → $ui_playgroup_nat_conflict            │   │
│  └────────────────────────────────┬─────────────────────────────────────┘   │
│                                   │                                          │
│  ════════════════════════════════════════════════════════════════════════   │
│  TITLE SCREEN ("Press Any Button") - Background init complete                │
│  ════════════════════════════════════════════════════════════════════════   │
│                                   │                                          │
│                      [User Selects Multiplayer]                              │
│                                   │                                          │
│                                   ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 4: Authentication                                               │   │
│  │   • ExpressLoginRequest or SilentLoginRequest                        │   │
│  │   • Validate EA Account credentials                                   │   │
│  │   • Check ACCOUNT_ID, PERSONA_NAME                                    │   │
│  │   ✗ EARLY EXIT: ERR_AUTHENTICATION_REQUIRED                          │   │
│  │   ✗ EARLY EXIT: ERR_DUPLICATE_LOGIN                                  │   │
│  │   ✗ EARLY EXIT: AUTH_ERR_INVALID_PASSWORD                            │   │
│  └────────────────────────────────┬─────────────────────────────────────┘   │
│                                   │                                          │
│                                   ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 5: Online Pass Validation                                       │   │
│  │   • Check pc/mod_onlinepass_%s.txt                                   │   │
│  │   • Verify entitlement (hasEntitlement)                              │   │
│  │   • Check trial status (OnlinePassTrialDuration)                     │   │
│  │   ✗ EARLY EXIT: AUTH_ERR_NO_SUCH_ENTITLEMENT                         │   │
│  │   ✗ EARLY EXIT: Trial expired                                        │   │
│  └────────────────────────────────┬─────────────────────────────────────┘   │
│                                   │                                          │
│                                   ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 6: Session Initialization                                       │   │
│  │   • fetchExtendedData()                                              │   │
│  │   • fetchClientConfig()                                              │   │
│  │   • getMatchmakingConfig()                                           │   │
│  │   ✗ EARLY EXIT: SDK_ERR_RPC_SEND_FAILED                              │   │
│  └────────────────────────────────┬─────────────────────────────────────┘   │
│                                   │                                          │
│  ════════════════════════════════════════════════════════════════════════   │
│  MULTIPLAYER MENU - Ready for matchmaking/game browser                       │
│  ════════════════════════════════════════════════════════════════════════   │
│                                   │                                          │
│                      [User Starts Matchmaking]                               │
│                                   │                                          │
│                                   ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 7: Matchmaking                                                  │   │
│  │   • startMatchmaking()                                               │   │
│  │   • NotifyMatchmakingAsyncStatus (progress)                          │   │
│  │   • Match found: JOIN_BY_MATCHMAKING                                 │   │
│  │   ✗ EARLY EXIT: NotifyMatchmakingFailed                              │   │
│  │   ✗ EARLY EXIT: GAMEMANAGER_ERR_MATCHMAKING_NO_JOINABLE_GAMES        │   │
│  │   ○ CANCEL: cancelMatchmaking()                                      │   │
│  └────────────────────────────────┬─────────────────────────────────────┘   │
│                                   │                                          │
│                                   ▼                                          │
│  ┌──────────────────────────────────────────────────────────────────────┐   │
│  │ PHASE 8: Game Session                                                 │   │
│  │   • CreateGameRequest or JoinGameResponse                            │   │
│  │   • NotifyGameCreated, NotifyPlayerJoinCompleted                     │   │
│  │   • Spawn: MPSpawnPointSelector                                      │   │
│  │   ✗ EARLY EXIT: SESSION_ERROR_GAME_SETUP_FAILED                      │   │
│  │   ✗ DISCONNECT: BLAZESERVER_CONN_LOST                                │   │
│  │   ✗ DISCONNECT: SESSION_TERMINATED                                   │   │
│  │   ○ LEAVE: leaveGameByGroup()                                        │   │
│  └──────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

### Early Termination Pathways

These are the code paths that cause multiplayer connection to fail or terminate:

#### Phase 1-2: Network/Redirector Failures

| Error Code | Cause | UI Message |
|------------|-------|------------|
| `SDK_ERR_DIRTYSOCK_UNINITIALIZED` | Network stack failure | N/A (crash) |
| `ERR_CANNOT_INIT_NETWORK` | Network init failed | `$ui_gpop_NoConnection` |
| `SDK_ERR_CONN_FAILED` | TCP connection failed | `$ui_gpop_connectionErrorTitle_mc` |
| `SDK_ERR_NOT_CONNECTED` | Not connected | `$ui_gpop_NoConnectionMessage_mc` |
| `ERR_CONNECTION_FAILED` | Redirector unreachable | `$ui_gpop_connectionLostTitle_mc` |
| `SDK_ERR_RPC_TIMEOUT` | Request timeout | `$ui_gpop_connectionErrorMessage_mc` |
| `SDK_ERR_SERVER_DISCONNECT` | Server disconnected | `$ui_gpop_hostHasDisconnected_mc` |

#### Phase 3: QoS/NAT Failures

| Error Code | Cause | UI Message |
|------------|-------|------------|
| `SDK_ERR_QOS_PINGSITE_NOT_INITIALIZED` | QoS not ready | Internal error |
| `NAT_TYPE_STRICT` | Strict NAT detected | `$ui_playgroup_nat_conflict` |
| `NAT_TYPE_STRICT_SEQUENTIAL` | Very restricted NAT | Warning |
| `CONNECTION_UNLIKELY` | Poor connectivity | Warning displayed |

#### Phase 4: Authentication Failures

| Error Code | Cause | UI Message |
|------------|-------|------------|
| `ERR_AUTHENTICATION_REQUIRED` | Not authenticated | `$ui_gpop_loginFailedTitle_mc` |
| `ERR_AUTHORIZATION_REQUIRED` | Not authorized | `$ui_gpop_loginFailedMessage_mc` |
| `ERR_DUPLICATE_LOGIN` | Already logged in | `$ui_gpop_personaLoginFailedMessage_mc` |
| `AUTH_ERR_INVALID_PASSWORD` | Wrong password | Login error |
| `AUTH_ERR_TOO_YOUNG` | Age restriction | Account error |
| `SDK_ERR_NO_MULTIPLAYER_PRIVILEGE` | No MP privilege | Entitlement error |

#### Phase 5: Online Pass Failures

| Condition | Result | UI Message |
|-----------|--------|------------|
| No Online Pass | Block MP access | `$ui_downloadOnlinePass` |
| Invalid code | Reject | `$ui_popup_onlineCodeInvalidTitle` |
| Code already used | Reject | `$ui_popup_onlineCodeAlreadyUsedTitle` |
| Trial expired | Block MP access | `$ui_popup_onlineTrialErrorMessage` |

#### Phase 6-8: Session/Game Failures

| Error Code | Cause | UI Message |
|------------|-------|------------|
| `SESSION_ERROR_GAME_SETUP_FAILED` | Game setup failed | `$ui_gpop_joinGameFailedTitle_mc` |
| `SESSION_TERMINATED` | Session ended | `$ui_gpop_connectionLostTitle_mc` |
| `SESSION_CANCELED` | Session cancelled | Variable |
| `SESSION_TIMED_OUT` | Session timeout | `$ui_gpop_connectionLostMessage_mc` |
| `BLAZESERVER_CONN_LOST` | Server lost | `$ui_gpop_hostHasDisconnected_mc` |
| `NotifyMatchmakingFailed` | MM failed | `$ui_quick_match_failed` |
| `GAMEMANAGER_ERR_MATCHMAKING_NO_JOINABLE_GAMES` | No games | `$ui_quick_match_failed` |

### NAT Type Detection

| NAT Type | Connectivity | Multiplayer Impact |
|----------|--------------|-------------------|
| `NAT_TYPE_OPEN` | Full | No restrictions |
| `NAT_TYPE_MODERATE` | Partial | Some restrictions |
| `NAT_TYPE_STRICT` | Limited | Major restrictions |
| `NAT_TYPE_STRICT_SEQUENTIAL` | Very limited | Severe restrictions |
| `NAT_TYPE_UNKNOWN` | Unknown | Variable |

**UPNP Support**:
- Command line: `-noupnp` disables UPNP
- States: `UPNP_ENABLED`, `UPNP_UNKNOWN`

### DirtySock User Agent

The game identifies itself to servers with:
```
User-Agent: ProtoHttp %d.%d/DS %d.%d.%d.%d
```

### Online Pass System

Dead Space 2 implements **Online Pass** DRM for multiplayer access:

| File/Setting | Purpose |
|--------------|---------|
| `pc/mod_onlinepass_%s.txt` | Pass configuration |
| `OnlinePassTrialDuration` | Trial period length |
| `OnlinePassValues` | Pass validation data |
| `hasEntitlement` | Entitlement check function |

### Key Connection Functions (Inferred)

| Function | Purpose | Phase |
|----------|---------|-------|
| `getServerInstance` | Get Blaze server from redirector | 2 |
| `fetchQosConfig` | Get QoS configuration | 3 |
| `fetchClientConfig` | Get client config | 6 |
| `expressLogin` / `silentLogin` | Quick/silent login | 4 |
| `loginPersona` | Login with persona | 4 |
| `hasEntitlement` | Check online pass | 5 |
| `startMatchmaking` | Begin matchmaking | 7 |
| `cancelMatchmaking` | Cancel matchmaking | 7 |
| `createPlaygroup` / `destroyPlaygroup` | Party management | Pre-7 |
| `leaveGameByGroup` | Leave game | 8 |

### Potential Server Emulation Interception Points

For private server implementation, key interception points:

| Level | Target | Notes |
|-------|--------|-------|
| **DNS** | `gosredirector.online.ea.com` | Redirect to custom server |
| **HTTP** | `/qos/*` endpoints | Return fake QoS data |
| **Blaze** | `getServerInstance` response | Point to custom game server |
| **Auth** | Login requests | Custom auth handling |

**⚠ Note**: The game uses **ProtoSSL** (TLS) for Blaze connections, requiring certificate manipulation for HTTPS interception.

---

## Relationship with activation.x86.dll

### Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     DEAD SPACE 2 ARCHITECTURE                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                    deadspace2.exe (46 MB)                  │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │ Solidshield Protection (QuFIo, 15 MB)               │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │ Game Engine (Visceral)                               │  │  │
│  │  │ • Rendering (DirectX 9)                              │  │  │
│  │  │ • Physics (Havok)                                    │  │  │
│  │  │ • Audio (RwAudioCore)                                │  │  │
│  │  │ • Game Logic                                         │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │ BlazeSDK (Multiplayer)                               │  │  │
│  │  │ • Matchmaking                                        │  │  │
│  │  │ • Game Sessions                                      │  │  │
│  │  │ • Player Management                                  │  │  │
│  │  │ • QoS                                                │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                          │                                       │
│                          │ LoadLibrary                           │
│                          ▼                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │              activation.x86.dll (6 MB)                     │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │ Solidshield Protection (S3, 5.6 MB)                 │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  │  ┌─────────────────────────────────────────────────────┐  │  │
│  │  │ DRM Activation                                       │  │  │
│  │  │ • License validation                                 │  │  │
│  │  │ • Hardware fingerprinting                            │  │  │
│  │  │ • activ.dat management                               │  │  │
│  │  │ • HTTPS activation                                   │  │  │
│  │  └─────────────────────────────────────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
│                                                                  │
├──────────────────────────────────────────────────────────────────┤
│                        NETWORK CONNECTIONS                        │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  deadspace2.exe ──────► gosredirector.online.ea.com (Blaze)     │
│                 ──────► QoS endpoints (HTTP)                     │
│                                                                  │
│  activation.x86.dll ──► EA Activation Server (HTTPS)            │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### Comparison

| Aspect | deadspace2.exe | activation.x86.dll |
|--------|----------------|-------------------|
| **Size** | 46 MB | 6 MB |
| **Protection** | Solidshield 2.0.3.1 | Solidshield 2.0.3.1 |
| **Encrypted Code** | 23.5 MB (.text) | 458 KB (.text) |
| **Unpacker Size** | 15.1 MB (QuFIo) | 5.6 MB (S3) |
| **Purpose** | Game + Multiplayer | DRM Only |
| **Network** | Blaze (TCP), QoS (HTTP) | HTTPS POST |
| **Hardcoded URLs** | EA server hostnames | None (passed in) |

---

## Unpacking Strategy

### Memory Dump Approach

Same technique used for activation.x86.dll:

1. **Launch Game**: Start Dead Space 2 via Steam/Proton
2. **Find Process**: `ps aux | grep -i dead`
3. **Wait for Decryption**: Solidshield decrypts .text at startup
4. **Dump Memory**: Use memory_dumper.py (modified for EXE)
5. **Extract Sections**: Save decrypted .text (~23.5 MB)
6. **Reconstruct PE**: Build unpacked executable

### Expected Results

| Section | Encrypted Size | Decrypted Content |
|---------|----------------|-------------------|
| .text | 23.5 MB | Game code, BlazeSDK, Havok, etc. |
| .bind | 352 KB | Import bindings |

### Challenges

- **Much larger target**: 23.5 MB vs 458 KB for DLL
- **Wine address remapping**: May load at different address
- **Timing**: Need to dump after full decryption
- **Integrity**: Game may have runtime checks

---

## String Statistics

| Metric | Value |
|--------|-------|
| **Total Strings** | 578,174 |
| **Unique Strings** | ~400,000 (estimated) |
| **Blaze-related** | ~500 |
| **Audio documentation** | ~100 KB |
| **Error messages** | ~2,000 |

---

## Security Assessment

### Anti-Tamper Mechanisms

1. **Code Encryption**: .text fully encrypted until runtime
2. **Integrity Checks**: Likely checksum verification
3. **Anti-Debug**: rdtsc/cpuid timing in unpacker
4. **Import Obfuscation**: Real imports resolved at runtime

### Potential Vulnerabilities

1. **Blaze Protocol**: Plain HTTP for QoS endpoints
2. **Hardcoded Servers**: Server hostnames in binary
3. **Old OpenSSL**: activation.x86.dll uses OpenSSL 1.0.0b (2010)

---

## References

- [REVERSE_ENGINEERING_NOTES.md](REVERSE_ENGINEERING_NOTES.md) - Sessions 10, 11, 12
- [ACTIVATION_TEXT_SECTION.md](ACTIVATION_TEXT_SECTION.md) - DLL function analysis
- [UNPACKING_DOCUMENTATION.md](UNPACKING_DOCUMENTATION.md) - Protection layer details

---

## Appendix A: Full Blaze Error Codes (Session 12 Update)

### SDK Errors (26 total)

| Offset | Error Code | Description |
|--------|------------|-------------|
| 0x1707E58 | SDK_ERR_DS_VERSION_MISMATCH | DirtySock version mismatch |
| 0x1707E80 | SDK_ERR_QOS_PINGSITE_NOT_INITIALIZED | QoS not ready |
| 0x1707EA8 | SDK_ERR_BLAZE_HUB_ALREADY_INITIALIZED | Double init |
| 0x1707ED0 | SDK_ERR_NO_SERVICE_NAME_PROVIDED | Missing service name |
| 0x1707EF4 | SDK_ERR_NO_CLIENT_VERSION_PROVIDED | Missing version |
| 0x1707F18 | SDK_ERR_NO_CLIENT_SKU_ID_PROVIDED | Missing SKU |
| 0x1707F3C | SDK_ERR_NO_CLIENT_NAME_PROVIDED | Missing client name |
| 0x1707F5C | SDK_ERR_USER_EXTENDED_DATA_NOT_AVAILABLE | User data unavailable |
| 0x1707F88 | SDK_ERR_MINIMUM_AGE_CHECK_FAILED | Age check failed |
| 0x1707FAC | SDK_ERR_DIRTYSOCK_UNINITIALIZED | Network not ready |
| 0x1707FCC | SDK_ERR_NO_MULTIPLAYER_PRIVILEGE | No MP privilege |
| 0x1707FF0 | SDK_ERR_DISCONNECT_OVERFLOW | Disconnect overflow |
| 0x170800C | SDK_ERR_SERVER_DISCONNECT | Server disconnected |
| 0x1708028 | SDK_ERR_CONN_FAILED | Connection failed |
| 0x170803C | SDK_ERR_TOS_UNAVAILABLE | Terms unavailable |
| 0x1708054 | SDK_ERR_NO_MEM | Out of memory |
| 0x1708064 | SDK_ERR_NO_CONSOLE_USERNAME | No console username |
| 0x1708080 | SDK_ERR_NO_CONSOLE_ID | No console ID |
| 0x1708098 | SDK_ERR_INVALID_USER_INDEX | Invalid user index |
| 0x17080B4 | SDK_ERR_NOT_CONNECTED | Not connected |
| 0x17080CC | SDK_ERR_INVALID_LOGIN_ACTION | Invalid login action |
| 0x17080EC | SDK_ERR_RPC_CANCELED | RPC cancelled |
| 0x1708104 | SDK_ERR_RPC_TIMEOUT | RPC timeout |
| 0x1708118 | SDK_ERR_IN_PROGRESS | Operation in progress |
| 0x170812C | SDK_ERR_INVALID_STATE | Invalid state |
| 0x1708144 | SDK_ERR_RPC_SEND_FAILED | RPC send failed |

### GameManager Errors (62 total - partial list)

```
GAMEMANAGER_ERR_NOT_MATCHMAKING_SESSION_OWNER
GAMEMANAGER_ERR_MATCHMAKING_NO_JOINABLE_GAMES
GAMEMANAGER_ERR_MATCHMAKING_USERSESSION_NOT_FOUND
GAMEMANAGER_ERR_UNKNOWN_MATCHMAKING_SESSION_ID
GAMEMANAGER_ERR_INVALID_MATCHMAKING_CRITERIA
GAMEMANAGER_ERR_TEAMS_DISABLED
GAMEMANAGER_ERR_INVALID_TEAM_CAPACITY
GAMEMANAGER_ERR_TEAM_FULL
GAMEMANAGER_ERR_INVALID_TEAM_ID_IN_TEAM_CAPACITIES_VECTOR
GAMEMANAGER_ERR_TEAM_NOT_ALLOWED
GAMEMANAGER_ERR_TOTAL_TEAM_CAPACITY_INVALID
GAMEMANAGER_ERR_DUPLICATE_TEAM_CAPACITY
GAMEMANAGER_ERR_INVALID_TEAM_CAPACITIES_VECTOR_SIZE
```

### User Session Errors

```
USER_ERR_INVALID_SESSION_INSTANCE
USER_ERR_DUPLICATE_SESSION
USER_ERR_SESSION_NOT_FOUND
SESSION_ERROR_GAME_SETUP_FAILED
```

### Authentication Errors (76 total - see Session 12 notes)

## Appendix B: Blaze Notification Events

```
NotifyMatchmakingAsyncStatus
NotifyMatchmakingFailed
NotifyPlayerJoinCompleted
NotifyPlayerRemoved
NotifyPlatformHostInitialized
NotifyHostMigrationStart
NotifyHostMigrationFinished
NotifySelectedAsHost
NotifyGameSettingsChange
NotifyPlayerCustomDataChange
NotifyGameStateChange
NotifyGameReportingIdChange
NotifyGameCreated
NotifyGameRemoved
NotifyGameSessionUpdated
NotifyGamePlayerStateChange
NotifyGamePlayerTeamChange
NotifyGameTeamIdChange
NotifyAdminListChange
```

## Appendix C: Game Manager Request Types

```
Blaze::GameManager::CreateGameResponse
Blaze::GameManager::DestroyGameRequest
Blaze::GameManager::DestroyGameResponse
Blaze::GameManager::JoinGameResponse
Blaze::GameManager::RemovePlayerRequest
Blaze::GameManager::RemovePlayerMasterRequest
Blaze::GameManager::BanPlayerRequest
Blaze::GameManager::BanPlayerMasterRequest
Blaze::GameManager::UpdateAdminListRequest
Blaze::GameManager::AdvanceGameStateRequest
Blaze::GameManager::ReplayGameRequest
Blaze::GameManager::ReturnDedicatedServerToPoolRequest
Blaze::GameManager::SetGameSettingsRequest
Blaze::GameManager::SetPlayerCustomDataRequest
Blaze::GameManager::SetPlayerTeamRequest
Blaze::GameManager::ChangeTeamIdRequest
Blaze::GameManager::MigrateHostRequest
Blaze::GameManager::MatchmakingDedicatedServerOverrideRequest
Blaze::GameManager::UpdateGameSessionRequest
Blaze::GameManager::UpdateGameHostMigrationStatusRequest
Blaze::GameManager::GetUserSetGameListSubscriptionRequest
Blaze::GameManager::GetGameListResponse
Blaze::GameManager::DestroyGameListRequest
Blaze::GameManager::SetNetworkQosRequest
```

## Appendix D: SDK Error Codes (Complete - Session 12)

See Appendix A for full error code table with .rdata offsets.

### Error Categories

| Category | Count | Prefix |
|----------|-------|--------|
| SDK Errors | 26 | SDK_ERR_* |
| Auth Errors | 76 | AUTH_ERR_* |
| GameManager Errors | 62 | GAMEMANAGER_ERR_* |
| **Total** | **164** | |

## Appendix E: Connection States

```
// Network States
NETWORK_INITIALIZE_TRANSITION
NETWORK_INITIALIZED
ERR_CANNOT_INIT_NETWORK

// Connection States
DISCONNECTED
CONNECT_TRANSITION
CONNECTED
ACTIVE_CONNECTED
CONNECTION_UNLIKELY

// Authentication States
AUTHENTICATE_TRANSITION
AUTHENTICATED

// Session States
SESSION_TERMINATED
SESSION_CANCELED
SESSION_TIMED_OUT
SESSION_ERROR_GAME_SETUP_FAILED
```

## Appendix F: NAT Types and UPNP

```
// NAT Detection Results
NAT_TYPE_UNKNOWN
NAT_TYPE_OPEN
NAT_TYPE_MODERATE
NAT_TYPE_STRICT
NAT_TYPE_STRICT_SEQUENTIAL

// UPNP States
UPNP_ENABLED
UPNP_UNKNOWN
```

## Appendix G: Environment Configurations

```
ENVIRONMENT_PROD      // Production (gosredirector.online.ea.com)
ENVIRONMENT_SCERT     // Secure/Certificate (gosredirector.scert.ea.com)
ENVIRONMENT_STEST     // Staging Test (gosredirector.stest.ea.com)
ENVIRONMENT_SDEV      // Development
```

## Appendix H: Playgroup (Party) System (Session 12 Update)

### Playgroup Classes (~30 total)

```
Blaze::Playgroups::CreatePlaygroupRequest
Blaze::Playgroups::JoinPlaygroupRequest
Blaze::Playgroups::JoinPlaygroupResponse
Blaze::Playgroups::LeavePlaygroupRequest
Blaze::Playgroups::DestroyPlaygroupRequest
Blaze::Playgroups::PlaygroupInfo
Blaze::Playgroups::PlaygroupMemberInfo
Blaze::Playgroups::NotifyJoinPlaygroup
Blaze::Playgroups::NotifyDestroyPlaygroup
```

### Playgroup State Constants (with offsets)

| Offset | Constant | Description |
|--------|----------|-------------|
| 0x1710BA8 | PLAYGROUP_CLOSED | Invite only |
| 0x1710BBC | PLAYGROUP_OPEN | Open to join |
| 0x1710BCC | PLAYGROUP_DESTROY_REASON_LEADER_CHANGE_DISABLED | Leader change blocked |
| 0x1710BFC | PLAYGROUP_DESTROY_REASON_DISCONNECTED | Leader disconnected |
| 0x1710C24 | PLAYGROUP_DESTROY_REASON_DEFAULT | Default destruction |
| 0x1710C48 | PLAYGROUP_MEMBER_REMOVE_TITLE_BASE_REASON | Base remove reason |
| 0x1710C74 | PLAYGROUP_MEMBER_REMOVE_REASON_KICKED | Kicked from party |
| 0x1710C9C | PLAYGROUP_MEMBER_REMOVE_REASON_DISCONNECTED | Member disconnected |
| 0x1710CC8 | PLAYGROUP_MEMBER_REMOVE_REASON_DEFAULT | Default removal |

### Functions

| Offset | Function | Purpose |
|--------|----------|--------|
| - | createPlaygroup | Create party |
| - | destroyPlaygroup | Disband party |
| 0x1701E20 | leaveGameByGroup | Leave game as party |
| 0x1701E34 | joinGameByGroup | Join game as party |

---

## Appendix I: Key Function Signatures (Session 12)

> Extracted from .rdata section with file offsets

### Connection Initialization

| Offset | Function | Purpose |
|--------|----------|---------|
| 0x170BBF0 | `getServerInstance` | Get Blaze server from redirector |
| 0x170FEB0 | `fetchQosConfig` | Get QoS configuration |
| 0x170FF70 | `fetchClientConfig` | Get client configuration |
| 0x1707AC8 | `fetchExtendedData` | Get extended user data |
| 0x1707240 | `CheckOnlineStatusRequest` | Check online connectivity |

### Authentication Functions

| Offset | Function | Purpose |
|--------|----------|---------|
| 0x170E060 | `expressLogin` | Quick login |
| 0x170E07C | `silentLogin` | Silent/background login |
| 0x170E0BC | `login` | Standard login |
| 0x170E01C | `loginPersona` | Login with specific persona |
| 0x170E00C | `logoutPersona` | Logout persona |
| 0x170E058 | `logout` | Full logout |
| 0x170E048 | `createPersona` | Create new persona |
| 0x170E03C | `getPersona` | Get persona info |
| 0x170E02C | `listPersonas` | List all personas |

### Entitlement Functions

| Offset | Function | Purpose |
|--------|----------|---------|
| 0x170DF0C | `hasEntitlement` | Check Online Pass |
| 0x170DF1C | `listEntitlements` | List all entitlements |
| 0x170DF30 | `grantEntitlement` | Grant entitlement |

### Game Session Functions

| Offset | Function | Purpose |
|--------|----------|---------|
| 0x1701F54 | `createGame` | Create game session |
| 0x1701EDC | `joinGame` | Join existing game |
| 0x1701F48 | `destroyGame` | Destroy game session |
| 0x1701E34 | `joinGameByGroup` | Join as party |
| 0x1701E20 | `leaveGameByGroup` | Leave as party |
| 0x1701D68 | `destroyGameList` | Destroy game list |

### Matchmaking Functions

| Offset | Function | Purpose |
|--------|----------|---------|
| 0x1701EB8 | `startMatchmaking` | Begin matchmaking |
| 0x1701EA4 | `cancelMatchmaking` | Cancel matchmaking |
| 0x1701D40 | `getMatchmakingConfig` | Get MM configuration |

---

## Appendix J: BlazeSDK Class Hierarchy (Session 12)

> 453 Blaze classes identified across 10 namespaces

### Namespace Distribution

| Namespace | Classes | Purpose |
|-----------|---------|---------|
| Blaze::GameManager | ~150 | Game sessions, matchmaking |
| Blaze::Authentication | ~50 | Login, personas, entitlements |
| Blaze::Redirector | ~15 | Server routing |
| Blaze::Playgroups | ~30 | Party/group system |
| Blaze::GameReporting | ~20 | Stats reporting |
| Blaze::Util | ~15 | Utilities, config |
| Blaze::Stats | ~10 | Player statistics |
| Blaze::Messaging | ~5 | Messaging system |
| Blaze::Association | ~5 | Friend lists |
| Blaze (root) | ~150 | Core types |

### Class Hierarchy Tree

```
Blaze (root namespace)
├── GameManager
│   ├── CreateGameRequest/Response
│   ├── JoinGameRequest/Response
│   ├── DestroyGameRequest/Response
│   ├── MatchmakingCustomCriteriaData
│   ├── MatchmakingCustomAsyncStatus
│   ├── HostInfo
│   ├── TeamCapacity
│   ├── SetNetworkQosRequest
│   ├── NotifyGameCreated
│   ├── NotifyGameRemoved
│   ├── NotifyPlayerJoinCompleted
│   ├── NotifyMatchmakingAsyncStatus
│   ├── NotifyMatchmakingFailed
│   └── ... (150+ classes)
│
├── Authentication
│   ├── LoginRequest
│   ├── SilentLoginRequest
│   ├── ExpressLoginRequest
│   ├── XboxLoginRequest
│   ├── PS3LoginRequest
│   ├── FullLoginResponse
│   ├── PersonaInfo
│   ├── AccountInfo
│   ├── SessionInfo
│   ├── Entitlement
│   ├── HasEntitlementRequest
│   └── ... (50+ classes)
│
├── Redirector
│   ├── ServerInstance
│   ├── ServerInstanceInfo
│   ├── ServerInstanceError
│   ├── ServerInstanceRequest
│   ├── ServerListRequest/Response
│   ├── ServerAddressInfo
│   ├── ServerEndpointInfo
│   ├── IpAddress
│   ├── XboxServerAddress
│   └── ... (15+ classes)
│
├── Playgroups
│   ├── CreatePlaygroupRequest
│   ├── JoinPlaygroupRequest/Response
│   ├── LeavePlaygroupRequest
│   ├── DestroyPlaygroupRequest
│   ├── PlaygroupInfo
│   ├── PlaygroupMemberInfo
│   ├── NotifyJoinPlaygroup
│   ├── NotifyDestroyPlaygroup
│   └── ... (30+ classes)
│
├── Util
│   ├── NetworkQosData
│   ├── FetchClientConfigRequest
│   └── ... (15+ classes)
│
└── Core Types
    ├── UserSessionDisconnectReason
    ├── UserSessionExtendedData
    ├── FetchExtendedDataRequest
    ├── CheckOnlineStatusRequest
    ├── NetworkInfo
    ├── QosConfigInfo
    ├── QosPingSiteInfo
    └── ... (150+ classes)
```

---

## Appendix K: Network Endpoints (Session 12)

### QoS Endpoints

| Offset | URL Pattern |
|--------|-------------|
| 0x17B6CD8 | `http://%s:%u/qos/qos?vers=%d` |
| 0x17B6D18 | `http://%s:%u/qos/firetype?vers=%d` |
| 0x17B6D44 | `http://%s:%u/qos/firewall?vers=%d` |

### Peer Discovery

| Offset | URL Pattern |
|--------|-------------|
| 0x17B8108 | `http://%s:%d/getPeerAddress?myIP=%s&myPort=%d&version=1.0` |

### DirtySock Identification

| Offset | String |
|--------|--------|
| 0x17B6B90 | `User-Agent: ProtoHttp %d.%d/DS %d.%d.%d.%d` |
| 0x17B8008 | `prototunnel-tunnel` |
| 0x17B801C | `prototunnel-global-recv` |
| 0x17B8034 | `prototunnel-global-send` |

---

## Appendix L: Online Pass System (Session 12)

### Configuration Paths

| Offset | Path | Purpose |
|--------|------|---------|
| 0x172C630 | `pc/mod_onlinepass_%s.txt` | Per-language config |
| 0x172C050 | `OnlinePassTrialDuration` | Trial length setting |
| 0x172C068 | `OnlinePassValues` | Validation data |

### UI Strings

| Offset | String | Purpose |
|--------|--------|---------|
| 0x172E9AC | `iMsgUIOnlinePassComplete` | Completion message |
| 0x172FE34 | `mOnlinePassDesc` | Description field |
| 0x172FE84 | `$ui_redeemCodeDescriptionOnlinePass` | Redeem code prompt |
| 0x172FEA8 | `$ui_downloadOnlinePass` | Download prompt |
| 0x172FEC0 | `$ui_downloadOnlinePassTickerText` | Ticker text |

---

## Appendix M: Command Line Arguments

| Offset | Argument | Purpose |
|--------|----------|---------|
| 0x16A4950 | `-disconnecttimeoutms` | Disconnect timeout |
| 0x17B6B10 | `-noupnp` | Disable UPNP |

---

## Appendix N: Analysis Limitations

### What We CAN Analyze (Static)

1. ✅ .rdata strings and constants (with offsets)
2. ✅ RTTI type information (partial - mostly Havok physics)
3. ✅ Import table (22 DLLs identified)
4. ✅ Solidshield entry point stub assembly
5. ✅ PE structure and section layout
6. ✅ Blaze class hierarchy (453 classes)
7. ✅ Function name signatures
8. ✅ Error codes (164 total)

### What We CANNOT Analyze (Static)

1. ❌ Actual function code (.text encrypted, entropy 8.00)
2. ❌ Vtable layouts (in encrypted .text)
3. ❌ Cross-references between functions
4. ❌ Blaze RPC handler implementations
5. ❌ Encryption/decryption routines

### Required for Full Analysis

To fully reverse engineer the multiplayer connection code:

1. **Memory Dump**: Dump decrypted .text section from running game under Wine/Proton
2. **IDA/Ghidra Import**: Load dumped EXE for decompilation
3. **Blaze Protocol RE**: Reverse the actual RPC handlers
4. **Network Capture**: Monitor Blaze traffic with Wireshark
5. **Server Emulation**: Build private server based on findings

> **Note**: The same memory dump technique used successfully for activation.x86.dll (Session 5) can be applied to deadspace2.exe.