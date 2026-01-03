# Dead Space 2 Binary Reverse Engineering Notes

## Binary Information

| Property | Value |
|----------|-------|
| **File** | `deadspace2.exe` |
| **Size** | 48,444,416 bytes (~48 MB) |
| **Format** | PE32 executable (Windows GUI) |
| **Architecture** | Intel i386 (32-bit) |
| **Sections** | 12 |
| **Linker** | MSVC 9.0 |

## Network Configuration

### EA Server Hostnames

| Server | Hostname | Purpose |
|--------|----------|---------|
| Redirector (Production) | `gosredirector.ea.com` | Main redirector |
| Redirector (Online) | `gosredirector.online.ea.com` | Online services |
| Redirector (SCERT) | `gosredirector.scert.ea.com` | Secure/cert testing |
| Redirector (STest) | `gosredirector.stest.ea.com` | Staging/test |
| Demangler | `demangler.ea.com` | NAT traversal helper |
| Peach | `peach.online.ea.com` | Unknown (possibly telemetry) |

### Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| 42127 | TCP/SSL | Redirector service |
| 7613 | TCP | Secondary/game port (found in binary) |

### SSL Certificates

The binary contains embedded certificates from:
- **Equifax Secure Certificate Authority** (root CA)
- **VeriSign Class 3 Secure Server CA**
- **VeriSign Trust Network**
- **OTG3 Certificate Authority**

## Game Codename: "Arson"

The internal codename for Dead Space 2 multiplayer is **"Arson"**.

Evidence:
- `Blaze::GameReporting::ArsonCTF_*` - CTF mode reporting
- `Blaze::GameReporting::ArsonLeague::*` - League/ranked mode
- `Blaze::GameReporting::ArsonClub::*` - Club/clan system
- `Blaze::GameReporting::ArsonMulti*` - General multiplayer

## Blaze Components Found (453 structures)

### Core Components

| Component | Namespace | Description |
|-----------|-----------|-------------|
| Redirector | `Blaze::Redirector` | Initial connection, server discovery |
| Authentication | `Blaze::Authentication` | Login, accounts, personas, entitlements |
| GameManager | `Blaze::GameManager` | Matchmaking, lobbies, game state |
| Stats | `Blaze::Stats` | Player statistics, leaderboards |
| GameReporting | `Blaze::GameReporting` | Post-game stats submission |
| Messaging | `Blaze::Messaging` | In-game messaging |
| Association | `Blaze::Association` | Friends, blocked lists |
| Util | `Blaze::Util` | Ping, config, telemetry |
| Playgroups | `Blaze::Playgroups` | Party/group system |

### Helper Types (Root Namespace)

```
Blaze::ClientInfo
Blaze::ClientMetrics
Blaze::NetworkInfo
Blaze::IpAddress
Blaze::IpPairAddress
Blaze::HostNameAddress
Blaze::GeoLocationData
Blaze::QosConfigInfo
Blaze::QosPingSiteInfo
Blaze::UserIdentification
Blaze::UserData
Blaze::UserStatus
Blaze::OnlineStatus
Blaze::XboxClientAddress
Blaze::XboxServerAddress
```

## Authentication Structures

### Login Flow
```
Blaze::Authentication::LoginRequest
Blaze::Authentication::LoginResponse
Blaze::Authentication::FullLoginResponse
Blaze::Authentication::SilentLoginRequest
Blaze::Authentication::ExpressLoginRequest
Blaze::Authentication::StressLoginRequest  (testing)
Blaze::Authentication::PS3LoginRequest
Blaze::Authentication::XboxLoginRequest
Blaze::Authentication::ConsoleLoginResponse
```

### Account Management
```
Blaze::Authentication::CreateAccountParameters
Blaze::Authentication::CreateAccountResponse
Blaze::Authentication::UpdateAccountRequest
Blaze::Authentication::UpdateAccountResponse
Blaze::Authentication::ValidateSessionKeyRequest
```

### Personas
```
Blaze::Authentication::PersonaInfo
Blaze::Authentication::PersonaDetails
Blaze::Authentication::PersonaRequest
Blaze::Authentication::CreatePersonaRequest
Blaze::Authentication::UpdatePersonaRequest
Blaze::Authentication::LoginPersonaRequest
Blaze::Authentication::ListPersonasResponse
Blaze::Authentication::GetPersonaResponse
```

### Entitlements
```
Blaze::Authentication::Entitlement
Blaze::Authentication::Entitlements
Blaze::Authentication::ListEntitlementsRequest
Blaze::Authentication::HasEntitlementRequest
Blaze::Authentication::PostEntitlementRequest
```

### Session
```
Blaze::Authentication::SessionInfo
Blaze::Authentication::GetAuthTokenResponse
Blaze::Authentication::GetHandoffTokenRequest
Blaze::Authentication::GetHandoffTokenResponse
```

## GameManager Structures

### Game Creation/Join
```
Blaze::GameManager::CreateGameRequest
Blaze::GameManager::CreateGameResponse
Blaze::GameManager::CreateGameStatus
Blaze::GameManager::JoinGameRequest
Blaze::GameManager::JoinGameResponse
Blaze::GameManager::JoinGameByUserListRequest
Blaze::GameManager::JoinGameByGroupMasterRequest
Blaze::GameManager::DestroyGameRequest
Blaze::GameManager::DestroyGameResponse
```

### Matchmaking
```
Blaze::GameManager::StartMatchmakingRequest
Blaze::GameManager::StartMatchmakingResponse
Blaze::GameManager::CancelMatchmakingRequest
Blaze::GameManager::MatchmakingSetupContext
Blaze::GameManager::MatchmakingCriteriaData
Blaze::GameManager::MatchmakingCriteriaError
Blaze::GameManager::MatchmakingAsyncStatus
Blaze::GameManager::FindGameStatus
```

### Game Browser
```
Blaze::GameManager::GetGameListRequest
Blaze::GameManager::GetGameListResponse
Blaze::GameManager::ListGamesResponse
Blaze::GameManager::GameBrowserDataList
Blaze::GameManager::GameBrowserGameData
Blaze::GameManager::GameBrowserMatchData
Blaze::GameManager::GameBrowserPlayerData
Blaze::GameManager::GameBrowserTeamInfo
```

### Game State
```
Blaze::GameManager::AdvanceGameStateRequest
Blaze::GameManager::ReplicatedGameData
Blaze::GameManager::ReplicatedGamePlayer
Blaze::GameManager::HostInfo
Blaze::GameManager::PlayerConnectionStatus
Blaze::GameManager::MigrateHostRequest
```

### Notifications (Server → Client)
```
Blaze::GameManager::NotifyGameCreated
Blaze::GameManager::NotifyGameRemoved
Blaze::GameManager::NotifyGameSetup
Blaze::GameManager::NotifyGameStateChange
Blaze::GameManager::NotifyGameSettingsChange
Blaze::GameManager::NotifyGameAttribChange
Blaze::GameManager::NotifyPlayerJoining
Blaze::GameManager::NotifyPlayerJoinCompleted
Blaze::GameManager::NotifyPlayerRemoved
Blaze::GameManager::NotifyPlayerStateChange
Blaze::GameManager::NotifyPlayerTeamChange
Blaze::GameManager::NotifyHostMigrationStart
Blaze::GameManager::NotifyHostMigrationFinished
Blaze::GameManager::NotifyMatchmakingFailed
Blaze::GameManager::NotifyMatchmakingAsyncStatus
Blaze::GameManager::NotifyAdminListChange
Blaze::GameManager::NotifyGameListUpdate
```

### Matchmaking Rules
```
Blaze::GameManager::DNFRulePrefs / Status
Blaze::GameManager::GameSizeRulePrefs / Status
Blaze::GameManager::GenericRulePrefs / Status
Blaze::GameManager::GeoLocationRuleCriteria / Status
Blaze::GameManager::HostBalancingRulePrefs / Status
Blaze::GameManager::HostViabilityRulePrefs / Status
Blaze::GameManager::PingSiteRulePrefs / Status
Blaze::GameManager::RankedGameRulePrefs / RankRuleStatus
Blaze::GameManager::RosterSizeRulePrefs
Blaze::GameManager::SkillRulePrefs / Status
Blaze::GameManager::TeamSizeRulePrefs / Status
```

## Stats Structures

```
Blaze::Stats::GetStatsRequest
Blaze::Stats::GetStatsResponse
Blaze::Stats::GetStatsByGroupRequest
Blaze::Stats::GetStatGroupRequest
Blaze::Stats::StatGroupResponse
Blaze::Stats::StatValues
Blaze::Stats::StatUpdate
Blaze::Stats::UpdateStatsRequest
Blaze::Stats::WipeStatsRequest
Blaze::Stats::LeaderboardStatsRequest
Blaze::Stats::LeaderboardGroupRequest
Blaze::Stats::LeaderboardGroupResponse
Blaze::Stats::LeaderboardStatValues
Blaze::Stats::LeaderboardStatValuesRow
Blaze::Stats::CenteredLeaderboardStatsRequest
Blaze::Stats::FilteredLeaderboardStatsRequest
Blaze::Stats::EntityStats
Blaze::Stats::EntityStatAggregates
Blaze::Stats::KeyScopes
Blaze::Stats::KeyScopeItem
Blaze::Stats::StatCategoryList
Blaze::Stats::StatDescs
```

## GameReporting Structures

### Dead Space Specific
```
Blaze::GameReporting::DeadSpace::Report
Blaze::GameReporting::DeadSpace::PlayerReport
```

### Arson CTF (Capture the Flag)
```
Blaze::GameReporting::ArsonCTF_EndGame::Report
Blaze::GameReporting::ArsonCTF_EndGame::PlayerReport
Blaze::GameReporting::ArsonCTF_EndGame::GameAttributes
Blaze::GameReporting::ArsonCTF_MidGame::Report
Blaze::GameReporting::ArsonCTF_Custom::ResultNotification
```

### Arson League (Ranked)
```
Blaze::GameReporting::ArsonLeague::Report
Blaze::GameReporting::ArsonLeague::PlayerReport
Blaze::GameReporting::ArsonLeague::AthleteReport
Blaze::GameReporting::ArsonLeague::GameAttributes
Blaze::GameReporting::ArsonLeague::OffensiveStats
Blaze::GameReporting::ArsonLeague::DefensiveStats
```

### Arson Club (Clans)
```
Blaze::GameReporting::ArsonClub::Report
Blaze::GameReporting::ArsonClub::ClubReport
Blaze::GameReporting::ArsonClub::PlayerReport
```

## Util Structures

```
Blaze::Util::PreAuthRequest
Blaze::Util::PreAuthResponse
Blaze::Util::PostAuthResponse
Blaze::Util::PingResponse
Blaze::Util::FetchClientConfigRequest
Blaze::Util::FetchConfigResponse
Blaze::Util::NetworkQosData
Blaze::Util::UserOptions
Blaze::Util::UserSettingsLoadRequest
Blaze::Util::UserSettingsLoadAllRequest
Blaze::Util::UserSettingsResponse
Blaze::Util::UserSettingsSaveRequest
Blaze::Util::GetTelemetryServerRequest
Blaze::Util::GetTelemetryServerResponse
Blaze::Util::GetTickerServerResponse
Blaze::Util::SetConnectionStateRequest
Blaze::Util::LocalizeStringsRequest
Blaze::Util::LocalizeStringsResponse
```

## Messaging Structures

```
Blaze::Messaging::ClientMessage
Blaze::Messaging::ServerMessage
Blaze::Messaging::SendMessageResponse
Blaze::Messaging::FetchMessageRequest
Blaze::Messaging::FetchMessageResponse
Blaze::Messaging::GetMessagesResponse
Blaze::Messaging::PurgeMessageRequest
Blaze::Messaging::TouchMessageRequest
```

## Association (Friends) Structures

```
Blaze::Association::GetListsRequest
Blaze::Association::GetListForUserRequest
Blaze::Association::UpdateListMembersRequest
Blaze::Association::UpdateListMembersResponse
Blaze::Association::ListInfo
Blaze::Association::ListMembers
Blaze::Association::ListMemberInfo
Blaze::Association::ListMemberId
Blaze::Association::ListIdentification
```

## Game Modes

Based on reporting structures and UI strings:

| Mode | Internal Name | Description |
|------|---------------|-------------|
| Team Objective | `ArsonCTF` | Humans vs Necromorphs objective mode |
| League | `ArsonLeague` | Ranked/competitive play |
| Club | `ArsonClub` | Clan battles |

## Maps

5 multiplayer maps identified (IDs 00-04):
- Map 00 (versusmap_name_00)
- Map 01 (versusmap_name_01)
- Map 02 (versusmap_name_02)
- Map 03 (versusmap_name_03)
- Map 04 (versusmap_name_04)

## Teams

| Team | Description |
|------|-------------|
| Human | Security team (Isaac-like characters) |
| Necromorph | Various necromorph types |

### Necromorph Types (Spawnable)
- Slasher
- Lurker
- Pack
- Puker
- Spitter

## Error Codes

### Authentication Errors (AUTH_ERR_*)
```
AUTH_ERR_BANNED
AUTH_ERR_DEACTIVATED
AUTH_ERR_DISABLED
AUTH_ERR_EXISTS
AUTH_ERR_EXPIRED_TOKEN
AUTH_ERR_INVALID_EMAIL
AUTH_ERR_INVALID_PASSWORD
AUTH_ERR_INVALID_PERSONA
AUTH_ERR_INVALID_SESSION_KEY
AUTH_ERR_INVALID_TOKEN
AUTH_ERR_INVALID_USER
AUTH_ERR_NO_ACCOUNT
AUTH_ERR_PERSONA_BANNED
AUTH_ERR_PERSONA_NOT_FOUND
AUTH_ERR_TOS_REQUIRED
AUTH_ERR_TOO_YOUNG
```

### GameManager Errors (GAMEMANAGER_ERR_*)
```
GAMEMANAGER_ERR_GAME_FULL
GAMEMANAGER_ERR_GAME_IN_PROGRESS
GAMEMANAGER_ERR_INVALID_GAME_ID
GAMEMANAGER_ERR_PLAYER_BANNED
GAMEMANAGER_ERR_PLAYER_NOT_FOUND
GAMEMANAGER_ERR_PERMISSION_DENIED
GAMEMANAGER_ERR_TEAM_FULL
GAMEMANAGER_ERR_MATCHMAKING_NO_JOINABLE_GAMES
GAMEMANAGER_ERR_HOST_MIGRATION_IN_PROGRESS
```

### Stats Errors (STATS_ERR_*)
```
STATS_ERR_STAT_NOT_FOUND
STATS_ERR_INVALID_LEADERBOARD_ID
STATS_ERR_RANK_OUT_OF_RANGE
STATS_ERR_DB_QUERY_FAILED
STATS_ERR_UNKNOWN_STAT_GROUP
```

## Combat Events (UI Strings)

```
$ui_mp_combat_text_kill_human
$ui_mp_combat_text_kill_necro
$ui_mp_combat_text_human_assist
$ui_mp_combat_text_necro_assist
$ui_mp_combat_text_human_suicide
$ui_mp_combat_text_necro_suicide
$ui_mp_combat_text_team_kill
$ui_mp_combat_text_complete_objective
$ui_mp_combat_text_objective_assist
$ui_mp_combat_text_rescue
$ui_mp_combat_text_heal
$ui_mp_combat_text_paired_damage
$ui_mp_combat_text_double_human
$ui_mp_combat_text_triple_human
$ui_mp_combat_text_quad_human
$ui_mp_combat_text_double_necro
$ui_mp_combat_text_triple_necro
$ui_mp_combat_text_quad_necro
$ui_mp_combat_text_kill_streak_5
$ui_mp_combat_text_kill_streak_10
$ui_mp_combat_text_kill_streak_20
```

## Join Methods

```
JOIN_BY_BROWSING
JOIN_BY_INVITES
JOIN_BY_MATCHMAKING
JOIN_BY_PLAYER
```

## List Types (Association)

```
LIST_TYPE_FRIEND
LIST_TYPE_BLOCK
LIST_TYPE_MUTE
LIST_TYPE_RECENTPLAYER
LIST_TYPE_UNKNOWN
LIST_TYPE_FIRST_CUSTOM
```

## Stat Periods

```
STAT_PERIOD_DAILY
STAT_PERIOD_WEEKLY
STAT_PERIOD_MONTHLY
STAT_PERIOD_ALL_TIME
```

## Stat Aggregation

```
STAT_AGGREGATE_TOP
STAT_AGGREGATE_MIN
STAT_AGGREGATE_AVERAGE
```

## Platform Identifiers

```
PLATFORM_PC
PLATFORM_PS3
PLATFORM_XBOX360
BLAZE_EXTERNAL_REF_TYPE_PS3
BLAZE_EXTERNAL_REF_TYPE_XBOX
BLAZE_EXTERNAL_REF_TYPE_WII
BLAZE_EXTERNAL_REF_TYPE_MOBILE
BLAZE_EXTERNAL_REF_TYPE_LEGACYPROFILEID
```

## NAT Traversal (Demangler)

The game uses EA's Demangler service for NAT traversal:
```
http://%s:%d/getPeerAddress?myIP=%s&myPort=%d&version=1.0
myIP=%s&myPort=%d&version=1.0&status=%s&gameFeatureID=%s
```

## Next Steps

1. [ ] Capture actual network traffic with SSL interception
2. [ ] Map component IDs to actual numeric values
3. [ ] Decode TDF field labels used in each structure
4. [ ] Implement missing notification handlers
5. [ ] Test with actual game client
6. [ ] Implement SSL support for redirector

## DLL Analysis

### activation.x86.dll

The EA activation DLL contains:
- **OpenSSL 1.0.0b** (16 Nov 2010) - Used for SSL/TLS
- STARTTLS support
- X.509 certificate handling
- Imports WS2_32.dll (Winsock)

This DLL likely handles the SSL connection to the redirector service.

### Key Dependencies

| DLL | Purpose |
|-----|---------|
| `WS2_32.dll` | Windows Sockets (networking) |
| `IPHLPAPI.DLL` | IP Helper API (network info) |
| `DSOUND.dll` | DirectSound (audio) |
| `d3d9.dll` | DirectX 9 (graphics) |
| `XINPUT1_3.dll` | Xbox controller input |
| `activation.x86.dll` | EA DRM + SSL/networking |

---

*Generated by reverse engineering deadspace2.exe using strings analysis*
*Date: 2026-01-03*
