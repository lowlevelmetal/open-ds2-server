#pragma once

#include <cstdint>
#include <vector>
#include <string>

namespace ds2 {
namespace network {

/**
 * Packet types for DS2 protocol
 * These will need to be discovered through reverse engineering
 */
enum class PacketType : uint16_t {
    // Connection
    Handshake           = 0x0001,
    HandshakeResponse   = 0x0002,
    Ping                = 0x0003,
    Pong                = 0x0004,
    Disconnect          = 0x0005,
    
    // Authentication
    AuthRequest         = 0x0010,
    AuthResponse        = 0x0011,
    AuthChallenge       = 0x0012,
    AuthChallengeResp   = 0x0013,
    
    // Lobby
    LobbyList           = 0x0020,
    LobbyCreate         = 0x0021,
    LobbyJoin           = 0x0022,
    LobbyLeave          = 0x0023,
    LobbyUpdate         = 0x0024,
    LobbyChat           = 0x0025,
    LobbyReady          = 0x0026,
    LobbyStart          = 0x0027,
    
    // Matchmaking
    MatchSearch         = 0x0030,
    MatchFound          = 0x0031,
    MatchCancel         = 0x0032,
    
    // Game
    GameStart           = 0x0040,
    GameEnd             = 0x0041,
    GameState           = 0x0042,
    PlayerUpdate        = 0x0043,
    PlayerDeath         = 0x0044,
    PlayerRespawn       = 0x0045,
    
    // Server query
    ServerInfo          = 0x0100,
    ServerInfoResponse  = 0x0101,
    PlayerList          = 0x0102,
    PlayerListResponse  = 0x0103,
    
    // Unknown/placeholder
    Unknown             = 0xFFFF
};

/**
 * Network packet structure
 */
struct Packet {
    PacketType type{PacketType::Unknown};
    uint32_t sequence{0};
    std::vector<uint8_t> data;
    
    Packet() = default;
    Packet(PacketType t) : type(t) {}
    Packet(PacketType t, const std::vector<uint8_t>& d) : type(t), data(d) {}
    
    /**
     * Get packet size (header + data)
     */
    size_t size() const { return 8 + data.size(); } // 2 type + 2 flags + 4 length
    
    /**
     * Clear packet data
     */
    void clear() {
        type = PacketType::Unknown;
        sequence = 0;
        data.clear();
    }
};

/**
 * Packet header structure
 * This is a placeholder - actual header format needs reverse engineering
 */
#pragma pack(push, 1)
struct PacketHeader {
    uint16_t magic;      // Magic identifier
    uint16_t type;       // Packet type
    uint32_t length;     // Data length
    uint32_t sequence;   // Sequence number
    uint32_t checksum;   // CRC32 or similar
};
#pragma pack(pop)

constexpr uint16_t PACKET_MAGIC = 0xD502; // Placeholder magic number (D5=DS)
constexpr size_t PACKET_HEADER_SIZE = sizeof(PacketHeader);
constexpr size_t MAX_PACKET_SIZE = 65536;

} // namespace network
} // namespace ds2
