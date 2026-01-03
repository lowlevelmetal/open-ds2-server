#include "game_handler.hpp"
#include "core/session.hpp"
#include "network/packet_handler.hpp"
#include "utils/buffer.hpp"
#include "utils/logger.hpp"

namespace ds2 {
namespace protocol {

void GameHandler::registerHandlers() {
    REGISTER_PACKET_HANDLER(GameStart, handleGameStart);
    REGISTER_PACKET_HANDLER(GameEnd, handleGameEnd);
    REGISTER_PACKET_HANDLER(GameState, handleGameState);
    REGISTER_PACKET_HANDLER(PlayerUpdate, handlePlayerUpdate);
    REGISTER_PACKET_HANDLER(PlayerDeath, handlePlayerDeath);
    REGISTER_PACKET_HANDLER(PlayerRespawn, handlePlayerRespawn);
    LOG_INFO("Game handlers registered");
}

void GameHandler::handleGameStart(std::shared_ptr<Session> session, const network::Packet& packet) {
    (void)packet;
    LOG_INFO("Game starting for player: " + session->getPlayerName());
    session->setState(SessionState::InGame);
    
    // TODO: Initialize game state for player
}

void GameHandler::handleGameEnd(std::shared_ptr<Session> session, const network::Packet& packet) {
    (void)packet;
    LOG_INFO("Game ending for player: " + session->getPlayerName());
    session->setState(SessionState::InLobby);
    
    // TODO: Process end-game stats, scores, etc.
}

void GameHandler::handleGameState(std::shared_ptr<Session> session, const network::Packet& packet) {
    if (session->getState() != SessionState::InGame) {
        return;
    }
    
    try {
        BufferReader reader(packet.data);
        
        // Read game state data
        // The exact format depends on the game protocol
        
        // TODO: Broadcast to other players in the same game
        
    } catch (const std::exception& e) {
        LOG_ERROR("Error processing game state: " + std::string(e.what()));
    }
}

void GameHandler::handlePlayerUpdate(std::shared_ptr<Session> session, const network::Packet& packet) {
    if (session->getState() != SessionState::InGame) {
        return;
    }
    
    try {
        BufferReader reader(packet.data);
        
        // Read player state
        // Position (x, y, z)
        float posX = reader.readFloat();
        float posY = reader.readFloat();
        float posZ = reader.readFloat();
        
        // Rotation (pitch, yaw)
        float pitch = reader.readFloat();
        float yaw = reader.readFloat();
        
        // Velocity
        float velX = reader.readFloat();
        float velY = reader.readFloat();
        float velZ = reader.readFloat();
        
        // Animation state
        uint8_t animState = reader.readU8();
        
        // Health
        uint16_t health = reader.readU16();
        
        (void)posX; (void)posY; (void)posZ;
        (void)pitch; (void)yaw;
        (void)velX; (void)velY; (void)velZ;
        (void)animState; (void)health;
        
        // TODO: Validate and broadcast to other players
        
    } catch (const std::exception& e) {
        LOG_ERROR("Error processing player update: " + std::string(e.what()));
    }
}

void GameHandler::handlePlayerDeath(std::shared_ptr<Session> session, const network::Packet& packet) {
    try {
        BufferReader reader(packet.data);
        
        uint32_t killerId = reader.readU32();
        uint8_t deathType = reader.readU8();  // Weapon, hazard, etc.
        
        LOG_INFO("Player " + session->getPlayerName() + " died (killer: " + 
                 std::to_string(killerId) + ", type: " + std::to_string(deathType) + ")");
        
        // TODO: Update scores, broadcast death event
        
    } catch (const std::exception& e) {
        LOG_ERROR("Error processing player death: " + std::string(e.what()));
    }
}

void GameHandler::handlePlayerRespawn(std::shared_ptr<Session> session, const network::Packet& packet) {
    try {
        BufferReader reader(packet.data);
        
        // Read respawn position (or use server-assigned spawn point)
        float spawnX = reader.readFloat();
        float spawnY = reader.readFloat();
        float spawnZ = reader.readFloat();
        
        (void)spawnX; (void)spawnY; (void)spawnZ;
        
        LOG_DEBUG("Player " + session->getPlayerName() + " respawning");
        
        // TODO: Validate spawn point, broadcast respawn
        
    } catch (const std::exception& e) {
        LOG_ERROR("Error processing player respawn: " + std::string(e.what()));
    }
}

} // namespace protocol
} // namespace ds2
