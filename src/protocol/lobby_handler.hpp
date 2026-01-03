#pragma once

#include <memory>
#include <vector>
#include <string>
#include <map>
#include <mutex>

#include "network/packet.hpp"

namespace ds2 {

class Session;

namespace protocol {

/**
 * Lobby information structure
 */
struct LobbyInfo {
    uint32_t id;
    std::string name;
    std::string map;
    std::string gameMode;
    uint8_t maxPlayers;
    uint8_t currentPlayers;
    bool inProgress;
    bool isPrivate;
    std::string password;
    uint32_t hostId;
    std::vector<uint32_t> playerIds;
};

/**
 * Lobby handler
 * Manages game lobbies and matchmaking
 */
class LobbyHandler {
public:
    static LobbyHandler& getInstance() {
        static LobbyHandler instance;
        return instance;
    }
    
    /**
     * Handle lobby list request
     */
    static void handleLobbyList(std::shared_ptr<Session> session, const network::Packet& packet);
    
    /**
     * Handle lobby creation
     */
    static void handleLobbyCreate(std::shared_ptr<Session> session, const network::Packet& packet);
    
    /**
     * Handle lobby join request
     */
    static void handleLobbyJoin(std::shared_ptr<Session> session, const network::Packet& packet);
    
    /**
     * Handle lobby leave
     */
    static void handleLobbyLeave(std::shared_ptr<Session> session, const network::Packet& packet);
    
    /**
     * Handle lobby chat message
     */
    static void handleLobbyChat(std::shared_ptr<Session> session, const network::Packet& packet);
    
    /**
     * Handle ready status change
     */
    static void handleLobbyReady(std::shared_ptr<Session> session, const network::Packet& packet);
    
    /**
     * Handle game start request
     */
    static void handleLobbyStart(std::shared_ptr<Session> session, const network::Packet& packet);
    
    /**
     * Register handlers
     */
    static void registerHandlers();
    
    // Lobby management
    LobbyInfo* getLobby(uint32_t lobbyId);
    LobbyInfo* getPlayerLobby(uint32_t playerId);
    std::vector<LobbyInfo> getPublicLobbies() const;
    
private:
    LobbyHandler() = default;
    
    uint32_t createLobby(const LobbyInfo& info);
    bool joinLobby(uint32_t lobbyId, uint32_t playerId);
    bool leaveLobby(uint32_t playerId);
    void destroyLobby(uint32_t lobbyId);
    void broadcastToLobby(uint32_t lobbyId, const network::Packet& packet);
    
    std::map<uint32_t, LobbyInfo> m_lobbies;
    std::map<uint32_t, uint32_t> m_playerLobby;  // playerId -> lobbyId
    mutable std::mutex m_mutex;
    uint32_t m_nextLobbyId{1};
};

} // namespace protocol
} // namespace ds2
