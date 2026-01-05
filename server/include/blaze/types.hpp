#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <map>
#include <variant>
#include <memory>

namespace ds2::blaze {

// =============================================================================
// Blaze Component IDs (from RE analysis)
// =============================================================================
enum class ComponentId : uint16_t {
    Authentication    = 0x01,   // Login, account management
    GameManager       = 0x04,   // Game sessions, matchmaking
    Redirector        = 0x05,   // Server redirection
    Stats             = 0x07,   // Statistics tracking
    Util              = 0x09,   // Utility functions (ping, config)
    Association       = 0x19,   // Friend lists, associations
    Playgroups        = 0x1E,   // Party/group management
    RSP               = 0x801,  // Room/session protocol
    UserSessions      = 0x7802, // User session management
};

// =============================================================================
// Blaze Message Types
// =============================================================================
enum class MessageType : uint16_t {
    Message           = 0x0000, // Request/Response
    Reply             = 0x1000, // Reply to request
    Notification      = 0x2000, // Async notification
    ErrorReply        = 0x3000, // Error response
};

// =============================================================================
// Blaze Error Codes
// =============================================================================
enum class BlazeError : uint32_t {
    Success           = 0x00000000,
    
    // General errors
    ERR_SYSTEM        = 0x00010001,
    ERR_TIMEOUT       = 0x00010002,
    ERR_INVALID_PARAM = 0x00010003,
    ERR_NOT_FOUND     = 0x00010004,
    
    // Authentication errors
    ERR_AUTH_REQUIRED = 0x00020001,
    ERR_INVALID_TOKEN = 0x00020002,
    ERR_SESSION_EXPIRED = 0x00020003,
    ERR_INVALID_CREDENTIALS = 0x00020004,
    
    // Game errors
    ERR_GAME_FULL     = 0x00040001,
    ERR_GAME_NOT_FOUND = 0x00040002,
};

// =============================================================================
// Redirector Commands
// =============================================================================
enum class RedirectorCommand : uint16_t {
    getServerInstance      = 0x01,  // Get Blaze server address
    getServerInstanceAddr  = 0x02,  // Get server address info
};

// =============================================================================
// Authentication Commands
// =============================================================================
enum class AuthCommand : uint16_t {
    login                  = 0x01,
    consoleLogin           = 0x02,
    silentLogin            = 0x03,
    logout                 = 0x04,
    createAccount          = 0x05,
    getAuthToken           = 0x06,
    loginSession           = 0x07,
    getPersona             = 0x08,
    expressLogin           = 0x14,
    originLogin            = 0x1C,
};

// =============================================================================
// Util Commands
// =============================================================================
enum class UtilCommand : uint16_t {
    ping                   = 0x01,
    setClientData          = 0x02,
    getClientData          = 0x03,
    localizeStrings        = 0x04,
    getTelemetryServer     = 0x05,
    getTickerServer        = 0x06,
    preAuth                = 0x07,
    postAuth               = 0x08,
    userSettingsLoad       = 0x09,
    userSettingsSave       = 0x0A,
    fetchClientConfig      = 0x0B,
    getSuspendedAccountInfo = 0x0C,
};

// =============================================================================
// GameManager Commands
// =============================================================================
enum class GameManagerCommand : uint16_t {
    createGame             = 0x01,
    destroyGame            = 0x02,
    advanceGameState       = 0x03,
    setGameSettings        = 0x04,
    setPlayerCapacity      = 0x05,
    setPresenceMode        = 0x06,
    setGameAttributes      = 0x07,
    setPlayerAttributes    = 0x08,
    joinGame               = 0x09,
    removePlayer           = 0x0A,
    startMatchmaking       = 0x0B,
    cancelMatchmaking      = 0x0C,
    finalizeGameCreation   = 0x0D,
    listGames              = 0x64,  // 0x64 = 100
    getGameDetails         = 0x65,
};

// =============================================================================
// Connection States (from RE analysis - 12 states)
// =============================================================================
enum class ConnectionState : uint8_t {
    DEACTIVATED         = 0,
    CONNECTING          = 1,
    CONNECTED           = 2,
    REDIRECTING         = 3,
    AUTHENTICATING      = 4,
    AUTHENTICATED       = 5,
    POST_AUTH           = 6,
    READY               = 7,
    DISCONNECTING       = 8,
    DISCONNECTED        = 9,
    RECONNECTING        = 10,
    ERROR_STATE         = 11,
};

// =============================================================================
// TDF (Tag Data Format) Types
// =============================================================================
enum class TdfType : uint8_t {
    Integer       = 0x00,  // Variable-length integer
    String        = 0x01,  // Null-terminated string
    Binary        = 0x02,  // Binary blob
    Struct        = 0x03,  // Nested structure
    List          = 0x04,  // List of elements
    Map           = 0x05,  // Key-value map
    Union         = 0x06,  // Tagged union
    IntList       = 0x07,  // List of integers
    Pair          = 0x08,  // Pair of integers (ObjectId/ObjectType)
    Triple        = 0x09,  // Triple (IP, Port, Protocol)
    Float         = 0x0A,  // Float value
};

// =============================================================================
// TDF Value Types
// =============================================================================
struct TdfValue;

using TdfInteger = int64_t;
using TdfString = std::string;
using TdfBinary = std::vector<uint8_t>;
using TdfList = std::vector<std::shared_ptr<TdfValue>>;
using TdfStruct = std::map<std::string, std::shared_ptr<TdfValue>>;
using TdfIntList = std::vector<int64_t>;

// Wrapper to distinguish Map from Struct in variant
struct TdfMapWrapper {
    std::map<std::string, std::shared_ptr<TdfValue>> data;
};

struct TdfPair {
    int64_t first;
    int64_t second;
};

struct TdfTriple {
    uint32_t ip;
    uint16_t port;
    uint16_t protocol;
};

// Variant to hold any TDF value
using TdfVariant = std::variant<
    TdfInteger,
    TdfString,
    TdfBinary,
    TdfStruct,
    TdfList,
    TdfMapWrapper,
    TdfIntList,
    TdfPair,
    TdfTriple,
    float
>;

struct TdfValue {
    std::string tag;      // 4-character tag (compressed to 3 bytes)
    TdfType type;
    TdfVariant value;
    
    TdfValue() = default;
    TdfValue(const std::string& t, TdfType ty, TdfVariant v)
        : tag(t), type(ty), value(std::move(v)) {}
};

// =============================================================================
// Blaze Packet Header (12 bytes)
// =============================================================================
#pragma pack(push, 1)
struct PacketHeader {
    uint16_t length;        // Payload length
    uint16_t component;     // Component ID
    uint16_t command;       // Command ID
    uint16_t error;         // Error code
    uint16_t msgType;       // Message type (request/reply/notification)
    uint16_t msgId;         // Message ID for request/response matching
};
#pragma pack(pop)

static_assert(sizeof(PacketHeader) == 12, "PacketHeader must be 12 bytes");

// =============================================================================
// Server Configuration
// =============================================================================
struct ServerConfig {
    // Redirector settings
    std::string redirector_host = "0.0.0.0";
    uint16_t redirector_port = 42127;
    
    // Blaze server settings
    std::string blaze_host = "0.0.0.0";
    uint16_t blaze_port = 10041;
    
    // QoS server settings  
    std::string qos_host = "0.0.0.0";
    uint16_t qos_port = 17502;
    
    // SSL certificate paths
    std::string ssl_cert_path = "certs/server.crt";
    std::string ssl_key_path = "certs/server.key";
    
    // Server identification
    std::string server_name = "DS2-Emulator";
    std::string server_version = "0.1.0";
};

} // namespace ds2::blaze
