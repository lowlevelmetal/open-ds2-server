# Dead Space 2 Protocol Reverse Engineering

## Overview

Dead Space 2 uses **EA's Blaze** backend system for multiplayer services. Blaze is EA's proprietary server infrastructure used across many EA titles.

## Key Findings

### Server Infrastructure

| Service | Hostname | Port |
|---------|----------|------|
| Redirector | `gosredirector.ea.com` | 42127 (SSL) |
| Redirector (Online) | `gosredirector.online.ea.com` | 42127 |
| Demangler | `demangler.ea.com` | - |

**Note:** Port 7613 is also referenced in the binary.

### Codename

The game's internal codename appears to be **"Arson"** based on reporting structures like:
- `ArsonCTF` (Capture the Flag mode)
- `ArsonLeague` (League/ranked play)
- `ArsonClub` (Clubs/teams)

### Blaze Components

The game uses the following Blaze components:

#### 1. Redirector Component
First point of contact - redirects client to appropriate game server.

```
Blaze::Redirector::ServerInstanceRequest
Blaze::Redirector::ServerInstanceInfo
Blaze::Redirector::ServerListRequest
Blaze::Redirector::ServerListResponse
```

#### 2. Authentication Component
Handles login, account creation, personas.

```
Blaze::Authentication::LoginRequest
Blaze::Authentication::LoginResponse
Blaze::Authentication::FullLoginResponse
Blaze::Authentication::CreateAccountRequest
Blaze::Authentication::CreatePersonaRequest
Blaze::Authentication::SessionInfo
Blaze::Authentication::Entitlements
Blaze::Authentication::ExpressLoginRequest
```

#### 3. GameManager Component
Core multiplayer - matchmaking, lobbies, game sessions.

```
Blaze::GameManager::CreateGameRequest
Blaze::GameManager::CreateGameResponse
Blaze::GameManager::JoinGameRequest
Blaze::GameManager::JoinGameResponse
Blaze::GameManager::StartMatchmakingRequest
Blaze::GameManager::StartMatchmakingResponse
Blaze::GameManager::GetGameListRequest
Blaze::GameManager::GetGameListResponse
Blaze::GameManager::NotifyGameCreated
Blaze::GameManager::NotifyPlayerJoining
Blaze::GameManager::NotifyPlayerRemoved
Blaze::GameManager::NotifyGameStateChange
Blaze::GameManager::NotifyHostMigrationStart
```

#### 4. Stats Component
Player statistics and leaderboards.

```
Blaze::Stats::GetStatsRequest
Blaze::Stats::GetStatsResponse
Blaze::Stats::LeaderboardStatsRequest
Blaze::Stats::LeaderboardGroupResponse
```

#### 5. Messaging Component
In-game messaging.

```
Blaze::Messaging::SendMessageResponse
Blaze::Messaging::FetchMessageRequest
Blaze::Messaging::GetMessagesResponse
```

#### 6. GameReporting Component
Post-game stats reporting.

```
Blaze::GameReporting::ArsonCTF_EndGame::Report
Blaze::GameReporting::ArsonLeague::PlayerReport
```

#### 7. AssociationLists Component
Friends lists, block lists.

```
Blaze::Association::GetListsRequest
Blaze::Association::UpdateListMembersRequest
```

### Game Modes

Based on the reporting structures:
- **CTF** - Capture the Flag
- **League** - Competitive/Ranked mode
- **Club** - Team-based play

## Blaze Protocol

### Connection Flow

1. Client connects to **Redirector** via SSL (port 42127)
2. Redirector returns appropriate game server address
3. Client connects to game server
4. Authentication handshake
5. Session established

### Packet Format (Blaze/Fire2 Protocol)

Blaze uses a binary protocol with the following header structure:

```
Offset | Size | Field
-------|------|------------------
0      | 2    | Packet size (big-endian)
2      | 2    | Component ID
4      | 2    | Command ID
6      | 2    | Error code
8      | 2    | Message type
10     | 2    | Message ID
12     | N    | TDF-encoded payload
```

### TDF Encoding

Blaze uses **TDF (Type Definition Format)** for serialization:
- Tag-based encoding
- Supports integers, strings, lists, maps, structs
- Little-endian integers

### Known Component IDs

| Component | ID (Estimated) |
|-----------|----------------|
| Authentication | 0x01 |
| GameManager | 0x04 |
| Redirector | 0x05 |
| Stats | 0x07 |
| Messaging | 0x0F |
| AssociationLists | 0x19 |
| GameReporting | 0x1C |

## Implementation Strategy

### Phase 1: Redirector Emulation
1. Set up SSL server on port 42127
2. Respond to `ServerInstanceRequest` with our server address
3. Use DNS override or hosts file to redirect `gosredirector.ea.com`

### Phase 2: Authentication
1. Implement mock authentication (accept all logins)
2. Generate valid session tokens
3. Return proper persona information

### Phase 3: GameManager
1. Implement lobby creation/joining
2. Handle matchmaking requests
3. Manage game sessions and player state

### Phase 4: Game State
1. Relay player updates between clients
2. Handle host migration
3. Manage game lifecycle (start, end, reporting)

## Tools & Resources

### Traffic Capture
- Wireshark with SSL decryption
- Fiddler for HTTP traffic
- Custom proxy for Blaze traffic

### Binary Analysis
- Ghidra/IDA for disassembly
- x64dbg/OllyDbg for debugging

### Related Projects
- [Arcadia](https://github.com/jacobtread/Arcadia) - ME3 Blaze server
- [Battlefield Server Emulators](https://github.com/BattlefieldRedux)

## Files of Interest

- `deadspace2.exe` - Main game executable (32-bit)
- `activation.x86.dll` - EA activation/DRM
- Certificate embedded in binary (Equifax Secure Certificate Authority)

## Next Steps

1. [x] Set up packet capture with SSL interception
2. [x] Document exact packet formats
3. [x] Implement Blaze packet parser
4. [x] Create redirector server
5. [ ] Test with actual game client
6. [ ] Implement SSL/TLS support for redirector
7. [ ] Implement full authentication flow
8. [ ] Implement game session management
9. [ ] Add database persistence for stats

## Implementation Status

### Completed
- TDF (Type Definition Format) encoder/decoder
- Blaze packet codec
- Component handler framework
- Redirector handler (GetServerInstance)
- Authentication handlers (Login, SilentLogin, Logout, GetAuthToken, ListPersonas, LoginPersona)
- Util handlers (Ping, FetchClientConfig, PreAuth, PostAuth, UserSettings)
- GameManager handlers (CreateGame, JoinGame, RemovePlayer, Matchmaking, ListGames)
- Stats handlers (GetStats, GetStatsByGroup, GetLeaderboard)

### In Progress
- SSL/TLS support for redirector port
- Network session management integration
- Full game state synchronization
