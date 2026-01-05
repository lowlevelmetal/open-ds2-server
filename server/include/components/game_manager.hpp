#pragma once

#include "blaze/component.hpp"
#include "blaze/types.hpp"
#include "network/client_connection.hpp"
#include <map>
#include <vector>
#include <mutex>

namespace ds2::components {

using network::ClientConnection;

/**
 * Game session information
 */
struct GameSession {
    uint64_t gameId;
    uint64_t hostUserId;
    std::string gameName;
    std::string mapName;
    std::string gameMode;
    uint32_t maxPlayers;
    uint32_t currentPlayers;
    std::vector<uint64_t> players;
    
    // Network info
    uint32_t hostIp;
    uint16_t hostPort;
};

/**
 * GameManager Component
 * 
 * Handles game sessions, matchmaking, and player management.
 * 
 * Commands:
 *   createGame (0x01)         - Create new game session
 *   destroyGame (0x02)        - Destroy game session
 *   joinGame (0x09)           - Join existing game
 *   removePlayer (0x0A)       - Remove player from game
 *   startMatchmaking (0x0B)   - Start matchmaking search
 *   cancelMatchmaking (0x0C)  - Cancel matchmaking
 *   listGames (0x64)          - List available games
 *   getGameDetails (0x65)     - Get game details
 */
class GameManager : public blaze::Component {
public:
    GameManager();
    
    std::unique_ptr<blaze::Packet> handlePacket(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    ) override;
    
private:
    std::unique_ptr<blaze::Packet> handleCreateGame(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    );
    
    std::unique_ptr<blaze::Packet> handleDestroyGame(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    );
    
    std::unique_ptr<blaze::Packet> handleJoinGame(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    );
    
    std::unique_ptr<blaze::Packet> handleListGames(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    );
    
    std::unique_ptr<blaze::Packet> handleStartMatchmaking(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    );
    
    std::unique_ptr<blaze::Packet> handleCancelMatchmaking(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    );
    
    // Game session management
    uint64_t createGameSession(const GameSession& session);
    bool destroyGameSession(uint64_t gameId);
    GameSession* getGameSession(uint64_t gameId);
    std::vector<GameSession> listGameSessions();
    
    std::map<uint64_t, GameSession> m_games;
    std::mutex m_gamesMutex;
    uint64_t m_nextGameId = 1;
};

} // namespace ds2::components
