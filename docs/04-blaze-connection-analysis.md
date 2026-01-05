# Dead Space 2 - BlazeSDK Connection Analysis

## Overview

This document details the multiplayer connection flow used by Dead Space 2 to connect to EA's Blaze servers. The game uses EA's BlazeSDK combined with DirtySock networking library.

## Connection State Machine

The game implements a 12-state connection state machine:

| State | ID | Name | Description |
|-------|-----|------|-------------|
| 0 | 0x00 | DEACTIVATED | Initial state, SDK not active |
| 1 | 0x01 | UNINITIALIZED | SDK loaded but not configured |
| 2 | 0x02 | INITIALIZE_TRANSITION | SDK initialization in progress |
| 3 | 0x03 | INITIALIZED | SDK ready for operation |
| 4 | 0x04 | PROFILE_LOAD_TRANSITION | Loading player profile |
| 5 | 0x05 | PROFILE_LOADED | Profile data loaded |
| 6 | 0x06 | NETWORK_INITIALIZE_TRANSITION | Network stack starting |
| 7 | 0x07 | NETWORK_INITIALIZED | Network ready |
| 8 | 0x08 | CONNECT_TRANSITION | Connecting to redirector |
| 9 | 0x09 | CONNECTED | Connected to Blaze server |
| 10 | 0x0A | AUTHENTICATE_TRANSITION | Authenticating with server |
| 11 | 0x0B | AUTHENTICATED | Fully connected and authenticated |

**Code Location**: State handler at 0x0060B9F0, state strings referenced from table at 0x0060BA90

## Server Infrastructure

### Redirector Servers

The redirector server determines which Blaze server to connect to:

| Environment | Hostname |
|-------------|----------|
| Production | gosredirector.online.ea.com |
| Test | gosredirector.stest.ea.com |

**Hostname Table**: 0x01B0196C (rdata)
- Format: [environment_id (4 bytes), hostname_ptr (4 bytes)]
- Selection code at: 0x00615800

### QoS (Quality of Service) Endpoints

The game performs NAT detection and QoS measurements:

- http://\<qos_server\>:\<port\>/qos/qos?vers=1
- http://\<qos_server\>:\<port\>/qos/firetype?vers=1  
- http://\<qos_server\>:\<port\>/qos/firewall?vers=1

**QoS URL Construction**: 0x01471AD0

### Peer Address Discovery

For NAT traversal:
- http://\<server\>:\<port\>/getPeerAddress?myIP=\<ip\>&myPort=\<port\>&version=1.0

## Authentication Flow

### Login Methods

1. **silentLogin** (0x006892A3) - Background login with saved credentials
2. **expressLogin** (0x006892B3) - Quick login flow  
3. **login** (0x0068927B) - Full login with credentials
4. **getAuthToken** (0x0068936B) - Retrieve authentication token

### Token Types

- AUTHTOKEN - Main authentication token
- PCLOGINTOKEN - PC-specific login token
- HANDOFFTOKEN - Session handoff token

## Key Components

### BlazeHub

Main SDK controller class:
- **String Reference**: BlazeHub::mLoginManagers at 0x01B01EFC
- **Error Code**: SDK_ERR_BLAZE_HUB_ALREADY_INITIALIZED (0x80180000)

### GameManager Component

Handles game session operations:

| Operation | Command ID Lookup |
|-----------|------------------|
| createGame | 0x00620180 |
| joinGame | 0x006201B8 |
| startMatchmaking | 0x006201C8 |
| cancelMatchmaking | 0x006201D0 |
| joinGameByGroup | 0x00620200 |

### Authentication Component

- **Name String**: AuthenticationComponent at 0x01B0F288
- **Dispatcher**: 0x00689200

## Network Protocol

### HTTP User-Agent

User-Agent: ProtoHttp %d.%d/DS %d.%d.%d.%d

Where:
- First two values: ProtoHttp version
- Last four values: DirtySock version

**Code Reference**: 0x0146FA4A

### Host Header

Used in HTTP requests to QoS and peer discovery servers.

## Key Function Addresses

| Function | Address | Purpose |
|----------|---------|---------|
| Redirector hostname selector | 0x00615800 | Selects server based on environment |
| State-to-string converter | 0x0060B9F0 | Debug logging |
| QoS URL builder | 0x01471AD0 | Constructs QoS request URLs |
| ProtoHttp request builder | 0x0146FA30 | Builds HTTP headers |
| BlazeHub error code lookup | 0x00649000 | Error code to string |
| getServerInstance lookup | 0x00678BC0 | Server instance operations |
| fetchQosConfig | 0x00691477 | QoS configuration |

## Connection Flow Summary

1. **Initialize SDK** (State 0-3)
   - Load BlazeSDK
   - Initialize BlazeHub
   - Set up memory allocators

2. **Load Profile** (State 3-5)
   - Load saved credentials
   - Prepare login data

3. **Initialize Network** (State 5-7)
   - Initialize DirtySock
   - Perform QoS measurements
   - Detect NAT type

4. **Connect to Server** (State 7-9)
   - Query redirector for server address
   - Establish SSL connection
   - Protocol handshake

5. **Authenticate** (State 9-11)
   - Send login credentials
   - Receive authentication token
   - Session established

## Notes for Server Emulation

To create a private server, the following would need to be implemented:

1. **Redirector Response** - Return a custom server address
2. **Blaze Protocol Handler** - Handle the binary Blaze RPC protocol
3. **Authentication Stub** - Accept any credentials or implement custom auth
4. **GameManager** - Handle game session creation/joining
5. **QoS Server** - Provide NAT detection and peer discovery

The redirector hostname can potentially be redirected via:
- DNS override (hosts file or custom DNS)
- Binary patching of hostname string
- Network proxy/MITM

## Blaze Protocol Components

The BlazeSDK uses a component-based RPC system. Each component handles a specific domain:

### Core Components

| Component | Purpose |
|-----------|---------|
| **Redirector** | Initial connection routing |
| **Authentication** | Login, tokens, entitlements |
| **Util** | Connection state, QoS config |
| **Association** | Friend lists, blocklists |
| **GameManager** | Game sessions, matchmaking |
| **GameReporting** | Statistics submission |
| **Messaging** | Player messaging |
| **Stats** | Leaderboards, statistics |
| **Playgroups** | Party/group management |

### Component Message Types

#### Authentication Component
- ExpressLoginRequest
- SilentLoginRequest
- LoginRequest
- LoginResponse / FullLoginResponse
- GetAuthTokenResponse
- GetHandoffTokenRequest/Response
- CreateAccountRequest/Response
- ListPersonasResponse
- HasEntitlementRequest
- Entitlement / Entitlements

#### GameManager Component
- CreateGameRequest/Response
- JoinGameRequest/Response
- DestroyGameRequest/Response
- StartMatchmakingRequest
- GetGameListRequest/Response
- UpdateGameSessionRequest
- HostInfo
- PlayerJoinCompleted (notification)
- PlayerRemoved (notification)
- HostMigrationStart/Finished (notifications)

#### Util Component
- SetConnectionStateRequest
- QosConfigInfo
- QosPingSiteInfo
- UpdatePingSiteLatencyRequest
- NetworkInfo
- GeoLocationData

#### GameReporting Component
- ResultNotification
- ArsonCTF_Custom::ResultNotification (game-specific)

### Network Address Types
- IpAddress
- IpPairAddress
- HostNameAddress
- XboxClientAddress
- XboxServerAddress

### User Data Types
- UserIdentification
- UserData
- UserStatus
- UserSessionExtendedData
- OnlineStatus
- ClientInfo
- ClientMetrics


## Complete Server List

### Redirector Servers (gosredirector)
| Environment | Hostname | Purpose |
|-------------|----------|---------|
| DEV | gosredirector.ea.com | Development server |
| SCERT | gosredirector.scert.ea.com | Secure certificate testing |
| STEST | gosredirector.stest.ea.com | Staging/testing |
| ONLINE | gosredirector.online.ea.com | **Production** |

### Other Servers
| Hostname | Purpose |
|----------|---------|
| demangler.ea.com | NAT demangling / peer address discovery |
| peach.online.ea.com | Unknown (possibly monitoring) |

### Environment Selection

The environment is selected based on a numeric ID:
- The game looks up the environment ID in a table at 0x01B01968
- Each entry contains: [environment_id, hostname_pointer]
- The matching hostname is returned from 0x01B0196C

**Environment ID Table** (at 0x01B01968):
```
Entry 0: [ID0] -> gosredirector.ea.com
Entry 1: [ID1] -> gosredirector.scert.ea.com  
Entry 2: [ID2] -> gosredirector.stest.ea.com
Entry 3: [ID3] -> gosredirector.online.ea.com
```

The environment is likely set via:
1. Command line argument
2. Configuration file
3. Compile-time constant for retail builds

## Default Port Numbers

Based on typical Blaze configuration:
- **Redirector**: Port 42127 (TCP/SSL)
- **Blaze Server**: Port 10041 (TCP/SSL) or assigned by redirector
- **QoS**: Port 17502 (HTTP/UDP)


## Key Implementation Details

### Redirector Port
- **Default Port**: 42127 (0xA48F)
- Set at address 0x0061587C in the connection initialization code
- Used with all redirector hostnames

### Connection Flow Implementation

1. **Environment Selection** (0x00615800)
   - Reads current environment ID from game state
   - Looks up hostname in table at 0x01B01968/0x01B0196C
   - Returns pointer to hostname string

2. **Port Assignment** (0x0061587C)
   - Default port 42127 used for redirector
   - Server may assign different port in redirect response

3. **State Transitions** (0x0060B9F0)
   - Switch statement on current state (0-11)
   - Returns state name string for logging

### DirtySock Integration

The game uses EA's DirtySock networking library:
- **User-Agent**: `ProtoHttp %d.%d/DS %d.%d.%d.%d`
- **Error**: `SDK_ERR_DIRTYSOCK_UNINITIALIZED`

### NetConnection Class

Located at string reference 0x01B96210:
- Manages low-level socket operations
- Handles SSL/TLS for secure connections
- Used by both QoS and Blaze communication

## Server Emulation Requirements

### Minimum Required Components

1. **DNS/Hosts Override**
   - Redirect gosredirector.online.ea.com to emulator
   - Optionally redirect demangler.ea.com

2. **Redirector Server** (Port 42127)
   - Accept SSL connection
   - Parse redirect request
   - Return Blaze server address

3. **Blaze Server** (Custom port)
   - Handle Blaze binary protocol
   - Implement core components:
     - Authentication (login responses)
     - Util (connection state)
     - GameManager (game sessions)

4. **QoS Server** (Optional)
   - HTTP endpoints for NAT detection
   - Can return hardcoded "open NAT" response

### Protocol Details Needed

To fully implement server emulation, further reverse engineering is needed for:
- Blaze packet header format
- TDF (Tag Data Format) encoding
- Component/Command ID mappings
- SSL certificate requirements (may need to disable validation)

### Potential Approaches

1. **Full Emulation**: Implement complete Blaze protocol server
2. **Proxy Mode**: MITM existing connections to understand protocol
3. **Binary Patch**: Modify game to connect without authentication
4. **LAN Mode**: If game supports direct IP connection

## Files and Memory Layout

### Binary Sections (deadspace2.exe)
| Section | Virtual Address | Size | Purpose |
|---------|-----------------|------|---------|
| .text | 0x00401000 | ~22.6 MB | Code (decrypted) |
| .rdata | 0x01AA1000 | ~1.6 MB | Strings, RTTI |
| .data | 0x01C6A000 | ~3.9 MB | Globals |

### Key Global Variables
| Address | Purpose |
|---------|---------|
| 0x01C6F138 | Connection state storage |
| 0x02030A44 | Secondary state |
| 0x020309F4 | Memory allocator pointer |
| 0x01B0196C | Redirector hostname table |

