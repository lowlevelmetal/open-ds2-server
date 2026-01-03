#pragma once

#include <memory>
#include "network/packet.hpp"

namespace ds2 {

class Session;

namespace protocol {

/**
 * Game handler
 * Handles in-game state synchronization
 */
class GameHandler {
public:
    /**
     * Handle game start
     */
    static void handleGameStart(std::shared_ptr<Session> session, const network::Packet& packet);
    
    /**
     * Handle game end
     */
    static void handleGameEnd(std::shared_ptr<Session> session, const network::Packet& packet);
    
    /**
     * Handle game state update
     */
    static void handleGameState(std::shared_ptr<Session> session, const network::Packet& packet);
    
    /**
     * Handle player position/state update
     */
    static void handlePlayerUpdate(std::shared_ptr<Session> session, const network::Packet& packet);
    
    /**
     * Handle player death event
     */
    static void handlePlayerDeath(std::shared_ptr<Session> session, const network::Packet& packet);
    
    /**
     * Handle player respawn
     */
    static void handlePlayerRespawn(std::shared_ptr<Session> session, const network::Packet& packet);
    
    /**
     * Register handlers
     */
    static void registerHandlers();
};

} // namespace protocol
} // namespace ds2
