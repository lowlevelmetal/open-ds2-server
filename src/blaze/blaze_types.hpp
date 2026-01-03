#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <map>
#include <variant>

namespace ds2 {
namespace blaze {

/**
 * Blaze Component IDs
 * These are the main service components in the Blaze protocol
 */
enum class ComponentId : uint16_t {
    Authentication      = 0x0001,
    Example            = 0x0003,
    GameManager        = 0x0004,
    Redirector         = 0x0005,
    PlayGroups         = 0x0006,
    Stats              = 0x0007,
    Util               = 0x0009,
    CensusData         = 0x000A,
    Clubs              = 0x000B,
    GameReporting      = 0x001C,
    Messaging          = 0x000F,
    AssociationLists   = 0x0019,
    GameReportingLegacy = 0x001C,
    UserSessions       = 0x7802,
};

/**
 * Blaze packet types
 */
enum class PacketType : uint16_t {
    Message            = 0x0000,  // Request/Response
    Reply              = 0x1000,  // Reply to a request
    Notification       = 0x2000,  // Async notification
    ErrorReply         = 0x3000,  // Error response
};

/**
 * Authentication Commands
 */
enum class AuthCommand : uint16_t {
    CreateAccount              = 0x000A,
    UpdateAccount              = 0x0014,
    UpdateParentalEmail        = 0x001C,
    ListUserEntitlements2      = 0x001D,
    GetAccount                 = 0x001E,
    GrantEntitlement           = 0x001F,
    ListEntitlements           = 0x0020,
    HasEntitlement             = 0x0021,
    GetUseCount                = 0x0022,
    DecrementUseCount          = 0x0023,
    GetAuthToken               = 0x0024,
    GetHandoffToken            = 0x0025,
    GetPasswordRules           = 0x0028,
    GrantEntitlement2          = 0x0029,
    Login                      = 0x001C,
    AcceptTos                  = 0x0033,
    GetTosInfo                 = 0x0034,
    ModifyEntitlement2         = 0x0035,
    ConsumeCode                = 0x0036,
    PasswordForgot             = 0x0037,
    GetTosContent              = 0x0038,
    GetPrivacyPolicyContent    = 0x0039,
    ListPersonaEntitlements2   = 0x003A,
    SilentLogin                = 0x0040,
    CheckAgeReq                = 0x0041,
    GetOptIn                   = 0x0042,
    EnableOptIn                = 0x0043,
    DisableOptIn               = 0x0044,
    ExpressLogin               = 0x0046,
    Logout                     = 0x0047,
    CreatePersona              = 0x0050,
    GetPersona                 = 0x0064,
    ListPersonas               = 0x0066,
    LoginPersona               = 0x006E,
    LogoutPersona              = 0x0078,
    DeletePersona              = 0x008C,
    DisablePersona             = 0x008D,
    ListDeviceAccounts         = 0x008F,
    XboxCreateAccount          = 0x0096,
    OriginLogin                = 0x0098,
    XboxAssociateAccount       = 0x00A0,
    XboxLogin                  = 0x00AA,
    PS3CreateAccount           = 0x00B4,
    PS3AssociateAccount        = 0x00BE,
    PS3Login                   = 0x00C8,
    ValidateSessionKey         = 0x00D2,
    CreateWalUserSession       = 0x00E6,
    AcceptLegalDocs            = 0x00F1,
    GetLegalDocsInfo           = 0x00F2,
    GetTermsOfServiceContent   = 0x00F6,
    DeviceLoginGuest           = 0x012C,
    
    // Notifications
    NotifyUserAdded            = 0x000A,
    NotifyUserRemoved          = 0x000B,
    NotifyUserUpdated          = 0x000C,
};

/**
 * GameManager Commands
 */
enum class GameManagerCommand : uint16_t {
    CreateGame                 = 0x0001,
    DestroyGame                = 0x0002,
    AdvanceGameState           = 0x0003,
    SetGameSettings            = 0x0004,
    SetPlayerCapacity          = 0x0005,
    SetGameAttributes          = 0x0007,
    SetPlayerAttributes        = 0x0008,
    JoinGame                   = 0x0009,
    RemovePlayer               = 0x000B,
    StartMatchmaking           = 0x000D,
    CancelMatchmaking          = 0x000E,
    FinalizeGameCreation       = 0x000F,
    ListGames                  = 0x0011,
    SetPlayerCustomData        = 0x0012,
    ReplayGame                 = 0x0013,
    ReturnDedicatedServerToPool = 0x0014,
    JoinGameByGroup            = 0x0015,
    LeaveGameByGroup           = 0x0016,
    MigrateGame                = 0x0017,
    UpdateGameHostMigrationStatus = 0x0018,
    ResetDedicatedServer       = 0x0019,
    UpdateGameSession          = 0x001A,
    BanPlayer                  = 0x001B,
    UpdateMeshConnection       = 0x001D,
    RemovePlayerMaster         = 0x001E,
    SetPlayerTeam              = 0x001F,
    ChangeTeamId               = 0x0020,
    GetGameDataFromId          = 0x001E,
    GetFullGameData            = 0x0028,
    GetMatchmakingConfig       = 0x0029,
    GetGameListSubscription    = 0x0032,
    DestroyGameList            = 0x0033,
    GetUserSetGameList         = 0x0037,
    GetFullUserSetGameList     = 0x0039,
    GetPlayerInfo              = 0x003D,
    SetNetworkQos              = 0x003E,
    GetNetworkConfig           = 0x003F,
    GetNumMatchmakingPlayers   = 0x0050,
    GetNumOfPlayerSessions     = 0x0051,
    RegisterDynamicDedicatedServer = 0x0064,
    UnregisterDynamicDedicatedServer = 0x0065,
    
    // Notifications
    NotifyMatchmakingFailed    = 0x000A,
    NotifyMatchmakingAsyncStatus = 0x000C,
    NotifyGameCreated          = 0x000F,
    NotifyGameRemoved          = 0x0010,
    NotifyGameSetup            = 0x0014,
    NotifyPlayerJoining        = 0x0015,
    NotifyJoiningPlayerInitiateConnections = 0x0016,
    NotifyPlayerJoinCompleted  = 0x001E,
    NotifyPlayerRemoved        = 0x0028,
    NotifyHostMigrationFinished = 0x003C,
    NotifyHostMigrationStart   = 0x0046,
    NotifyPlatformHostInitialized = 0x0047,
    NotifyGameAttribChange     = 0x0050,
    NotifyPlayerAttribChange   = 0x005A,
    NotifyPlayerCustomDataChange = 0x005F,
    NotifyGameStateChange      = 0x0064,
    NotifyGameSettingsChange   = 0x006E,
    NotifyGameCapacityChange   = 0x006F,
    NotifyGameTeamIdChange     = 0x0070,
    NotifyGameReset            = 0x0073,
    NotifyGameReportingIdChange = 0x0074,
    NotifyGameSessionUpdated   = 0x00C9,
    NotifyGamePlayerStateChange = 0x00CA,
    NotifyGamePlayerTeamChange = 0x00CB,
    NotifyGameListUpdate       = 0x00C8,
    NotifyAdminListChange      = 0x00D6,
    NotifyCreateDynamicDedicatedServerGame = 0x00DC,
    NotifySelectedAsHost       = 0x00E6,
};

/**
 * Redirector Commands
 */
enum class RedirectorCommand : uint16_t {
    GetServerInstance          = 0x0001,
    GetServerList              = 0x0002,
};

/**
 * Util Commands
 */
enum class UtilCommand : uint16_t {
    FetchClientConfig          = 0x0001,
    Ping                       = 0x0002,
    SetClientData              = 0x0003,
    LocalizeStrings            = 0x0004,
    GetTelemetryServer         = 0x0005,
    GetTickerServer            = 0x0006,
    PreAuth                    = 0x0007,
    PostAuth                   = 0x0008,
    UserSettingsLoad           = 0x000A,
    UserSettingsSave           = 0x000B,
    UserSettingsLoadAll        = 0x000C,
    DeleteUserSettings         = 0x000E,
    FilterForProfanity         = 0x0014,
    FetchQosConfig             = 0x0016,
    SetClientMetrics           = 0x0017,
    SetConnectionState         = 0x0018,
    GetPssConfig               = 0x0019,
    GetUserOptions             = 0x001A,
    SetUserOptions             = 0x001B,
    SuspendUserPing            = 0x001C,
};

/**
 * Stats Commands
 */
enum class StatsCommand : uint16_t {
    GetStatDescs               = 0x0001,
    GetStats                   = 0x0002,
    GetStatGroupList           = 0x0003,
    GetStatGroup               = 0x0004,
    GetStatsByGroup            = 0x0005,
    GetDateRange               = 0x0006,
    GetEntityCount             = 0x0007,
    GetLeaderboardGroup        = 0x000A,
    GetLeaderboardFolderGroup  = 0x000B,
    GetLeaderboard             = 0x000C,
    GetCenteredLeaderboard     = 0x000D,
    GetFilteredLeaderboard     = 0x000E,
    GetKeyScopesMap            = 0x000F,
    GetStatsByGroupAsync       = 0x0010,
    GetLeaderboardTreeAsync    = 0x0011,
    GetLeaderboardEntityCount  = 0x0012,
    GetStatCategoryList        = 0x0013,
    GetPeriodIds               = 0x0014,
    GetLeaderboardRaw          = 0x0015,
    GetCenteredLeaderboardRaw  = 0x0016,
    GetFilteredLeaderboardRaw  = 0x0017,
    ChangeKeyscopeValue        = 0x0018,
};

/**
 * Blaze packet header
 */
#pragma pack(push, 1)
struct PacketHeader {
    uint16_t length;       // Packet length (big-endian, excluding this field)
    uint16_t component;    // Component ID
    uint16_t command;      // Command ID
    uint16_t errorCode;    // Error code (0 for success)
    uint16_t msgType;      // Message type (request, reply, notification)
    uint16_t msgId;        // Message ID (for request/reply matching)
};
#pragma pack(pop)

constexpr size_t HEADER_SIZE = sizeof(PacketHeader);

/**
 * TDF (Type Definition Format) Tag Types
 */
enum class TdfType : uint8_t {
    Integer    = 0x00,  // Variable-length integer
    String     = 0x01,  // UTF-8 string
    Binary     = 0x02,  // Binary blob
    Struct     = 0x03,  // Nested structure
    List       = 0x04,  // List/array
    Map        = 0x05,  // Key-value map
    Union      = 0x06,  // Tagged union
    IntList    = 0x07,  // List of integers
    ObjectType = 0x08,  // Object type ID
    ObjectId   = 0x09,  // Object instance ID
    Float      = 0x0A,  // Floating point
    TimeValue  = 0x0B,  // Timestamp
    Max        = 0x0C,
    Invalid    = 0xFF,
};

/**
 * TDF Tag - 4 character label + type
 */
struct TdfTag {
    char label[4];  // 3-char label + padding (big-endian encoded)
    TdfType type;
    
    std::string getLabelString() const {
        // Decode the 3-character label from the tag
        std::string result;
        uint32_t encoded = (label[0] << 24) | (label[1] << 16) | (label[2] << 8) | label[3];
        // Blaze uses base-32 encoding for tags
        // Each character is 6 bits
        result += static_cast<char>(0x20 + ((encoded >> 26) & 0x3F));
        result += static_cast<char>(0x20 + ((encoded >> 20) & 0x3F));
        result += static_cast<char>(0x20 + ((encoded >> 14) & 0x3F));
        result += static_cast<char>(0x20 + ((encoded >> 8) & 0x3F));
        return result;
    }
};

/**
 * Blaze error codes
 */
enum class BlazeError : uint16_t {
    Success                    = 0x0000,
    ComponentNotFound          = 0x0002,
    CommandNotFound            = 0x0003,
    AuthenticationRequired     = 0x0006,
    InvalidParameters          = 0x0009,
    SessionNotFound            = 0x000C,
    Timeout                    = 0x000D,
    
    // Authentication errors
    AuthInvalidUser            = 0x0065,
    AuthInvalidPassword        = 0x0066,
    AuthAccountLocked          = 0x0067,
    AuthAccountDisabled        = 0x0068,
    AuthPersonaNotFound        = 0x006A,
    AuthInvalidSession         = 0x006B,
    
    // GameManager errors
    GameNotFound               = 0x0190,
    GameFull                   = 0x0191,
    GameInProgress             = 0x0192,
    PlayerNotFound             = 0x0193,
    InvalidGameState           = 0x0194,
    MatchmakingFailed          = 0x0195,
};

/**
 * Game state for GameManager
 */
enum class GameState : uint8_t {
    Initializing       = 0x01,
    PreGame            = 0x02,
    InGame             = 0x82,
    PostGame           = 0x04,
    Migrating          = 0x05,
    Destructing        = 0x06,
    ResetGame          = 0x07,
};

/**
 * Player state
 */
enum class PlayerState : uint8_t {
    Reserved           = 0x00,
    Queued             = 0x01,
    ActiveConnecting   = 0x02,
    ActiveConnected    = 0x04,
    ActiveMigrating    = 0x08,
    ActiveKicked       = 0x10,
};

/**
 * Blaze packet
 */
struct Packet {
    ComponentId component;
    uint16_t command;
    PacketType type;
    uint16_t msgId;
    uint16_t errorCode;
    std::vector<uint8_t> payload;
    
    Packet() : component(ComponentId::Util), command(0), type(PacketType::Message), 
               msgId(0), errorCode(0) {}
};

} // namespace blaze
} // namespace ds2
