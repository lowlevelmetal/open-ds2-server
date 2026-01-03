#include "lobby_handler.hpp"
#include "core/session.hpp"
#include "network/packet_handler.hpp"
#include "utils/buffer.hpp"
#include "utils/logger.hpp"

#include <algorithm>

namespace ds2 {
namespace protocol {

void LobbyHandler::registerHandlers() {
    REGISTER_PACKET_HANDLER(LobbyList, handleLobbyList);
    REGISTER_PACKET_HANDLER(LobbyCreate, handleLobbyCreate);
    REGISTER_PACKET_HANDLER(LobbyJoin, handleLobbyJoin);
    REGISTER_PACKET_HANDLER(LobbyLeave, handleLobbyLeave);
    REGISTER_PACKET_HANDLER(LobbyChat, handleLobbyChat);
    REGISTER_PACKET_HANDLER(LobbyReady, handleLobbyReady);
    REGISTER_PACKET_HANDLER(LobbyStart, handleLobbyStart);
    LOG_INFO("Lobby handlers registered");
}

void LobbyHandler::handleLobbyList(std::shared_ptr<Session> session, const network::Packet& packet) {
    (void)packet;
    LOG_DEBUG("Lobby list request from " + session->getPlayerName());
    
    auto& handler = getInstance();
    auto lobbies = handler.getPublicLobbies();
    
    network::Packet response(network::PacketType::LobbyList);
    BufferWriter writer;
    
    writer.writeU16(static_cast<uint16_t>(lobbies.size()));
    
    for (const auto& lobby : lobbies) {
        writer.writeU32(lobby.id);
        writer.writeLString(lobby.name);
        writer.writeLString(lobby.map);
        writer.writeLString(lobby.gameMode);
        writer.writeU8(lobby.currentPlayers);
        writer.writeU8(lobby.maxPlayers);
        writer.writeU8(lobby.inProgress ? 1 : 0);
        writer.writeU8(lobby.isPrivate ? 1 : 0);
    }
    
    response.data = writer.take();
    session->sendPacket(response);
}

void LobbyHandler::handleLobbyCreate(std::shared_ptr<Session> session, const network::Packet& packet) {
    LOG_DEBUG("Lobby create request from " + session->getPlayerName());
    
    try {
        BufferReader reader(packet.data);
        
        LobbyInfo lobby;
        lobby.name = reader.readLString();
        lobby.map = reader.readLString();
        lobby.gameMode = reader.readLString();
        lobby.maxPlayers = reader.readU8();
        lobby.isPrivate = reader.readU8() != 0;
        
        if (lobby.isPrivate) {
            lobby.password = reader.readLString();
        }
        
        lobby.hostId = session->getPlayerId();
        lobby.currentPlayers = 1;
        lobby.inProgress = false;
        lobby.playerIds.push_back(session->getPlayerId());
        
        auto& handler = getInstance();
        uint32_t lobbyId = handler.createLobby(lobby);
        
        // Send response
        network::Packet response(network::PacketType::LobbyCreate);
        BufferWriter writer;
        writer.writeU8(1);  // Success
        writer.writeU32(lobbyId);
        response.data = writer.take();
        session->sendPacket(response);
        
        session->setState(SessionState::InLobby);
        LOG_INFO("Lobby created: " + lobby.name + " (ID: " + std::to_string(lobbyId) + ")");
        
    } catch (const std::exception& e) {
        LOG_ERROR("Error creating lobby: " + std::string(e.what()));
        
        network::Packet response(network::PacketType::LobbyCreate);
        BufferWriter writer;
        writer.writeU8(0);  // Failure
        writer.writeU32(0);
        writer.writeLString("Failed to create lobby");
        response.data = writer.take();
        session->sendPacket(response);
    }
}

void LobbyHandler::handleLobbyJoin(std::shared_ptr<Session> session, const network::Packet& packet) {
    LOG_DEBUG("Lobby join request from " + session->getPlayerName());
    
    try {
        BufferReader reader(packet.data);
        
        uint32_t lobbyId = reader.readU32();
        std::string password;
        
        if (reader.hasMore()) {
            password = reader.readLString();
        }
        
        auto& handler = getInstance();
        auto* lobby = handler.getLobby(lobbyId);
        
        if (!lobby) {
            // Lobby not found
            network::Packet response(network::PacketType::LobbyJoin);
            BufferWriter writer;
            writer.writeU8(0);
            writer.writeLString("Lobby not found");
            response.data = writer.take();
            session->sendPacket(response);
            return;
        }
        
        if (lobby->currentPlayers >= lobby->maxPlayers) {
            network::Packet response(network::PacketType::LobbyJoin);
            BufferWriter writer;
            writer.writeU8(0);
            writer.writeLString("Lobby is full");
            response.data = writer.take();
            session->sendPacket(response);
            return;
        }
        
        if (lobby->isPrivate && lobby->password != password) {
            network::Packet response(network::PacketType::LobbyJoin);
            BufferWriter writer;
            writer.writeU8(0);
            writer.writeLString("Invalid password");
            response.data = writer.take();
            session->sendPacket(response);
            return;
        }
        
        if (handler.joinLobby(lobbyId, session->getPlayerId())) {
            network::Packet response(network::PacketType::LobbyJoin);
            BufferWriter writer;
            writer.writeU8(1);  // Success
            writer.writeU32(lobbyId);
            writer.writeLString(lobby->name);
            writer.writeLString(lobby->map);
            writer.writeLString(lobby->gameMode);
            response.data = writer.take();
            session->sendPacket(response);
            
            session->setState(SessionState::InLobby);
            LOG_INFO(session->getPlayerName() + " joined lobby " + lobby->name);
            
            // TODO: Notify other players in lobby
        }
        
    } catch (const std::exception& e) {
        LOG_ERROR("Error joining lobby: " + std::string(e.what()));
    }
}

void LobbyHandler::handleLobbyLeave(std::shared_ptr<Session> session, const network::Packet& packet) {
    (void)packet;
    LOG_DEBUG("Lobby leave from " + session->getPlayerName());
    
    auto& handler = getInstance();
    handler.leaveLobby(session->getPlayerId());
    
    session->setState(SessionState::Authenticated);
    
    network::Packet response(network::PacketType::LobbyLeave);
    BufferWriter writer;
    writer.writeU8(1);  // Success
    response.data = writer.take();
    session->sendPacket(response);
}

void LobbyHandler::handleLobbyChat(std::shared_ptr<Session> session, const network::Packet& packet) {
    try {
        BufferReader reader(packet.data);
        std::string message = reader.readLString();
        
        auto& handler = getInstance();
        auto* lobby = handler.getPlayerLobby(session->getPlayerId());
        
        if (!lobby) {
            return;
        }
        
        // Broadcast to all players in lobby
        network::Packet chatPacket(network::PacketType::LobbyChat);
        BufferWriter writer;
        writer.writeU32(session->getPlayerId());
        writer.writeLString(session->getPlayerName());
        writer.writeLString(message);
        chatPacket.data = writer.take();
        
        handler.broadcastToLobby(lobby->id, chatPacket);
        
    } catch (const std::exception& e) {
        LOG_ERROR("Error processing lobby chat: " + std::string(e.what()));
    }
}

void LobbyHandler::handleLobbyReady(std::shared_ptr<Session> session, const network::Packet& packet) {
    try {
        BufferReader reader(packet.data);
        bool ready = reader.readU8() != 0;
        
        LOG_DEBUG(session->getPlayerName() + " ready status: " + (ready ? "ready" : "not ready"));
        
        // TODO: Track ready status and broadcast to lobby
        
    } catch (const std::exception& e) {
        LOG_ERROR("Error processing ready status: " + std::string(e.what()));
    }
}

void LobbyHandler::handleLobbyStart(std::shared_ptr<Session> session, const network::Packet& packet) {
    (void)packet;
    
    auto& handler = getInstance();
    auto* lobby = handler.getPlayerLobby(session->getPlayerId());
    
    if (!lobby || lobby->hostId != session->getPlayerId()) {
        LOG_WARN("Non-host tried to start game");
        return;
    }
    
    LOG_INFO("Starting game in lobby: " + lobby->name);
    lobby->inProgress = true;
    
    // TODO: Transition all players to game state
    // This would involve sending game start packets with connection info
}

// Instance methods

uint32_t LobbyHandler::createLobby(const LobbyInfo& info) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    uint32_t id = m_nextLobbyId++;
    LobbyInfo lobby = info;
    lobby.id = id;
    
    m_lobbies[id] = lobby;
    m_playerLobby[info.hostId] = id;
    
    return id;
}

bool LobbyHandler::joinLobby(uint32_t lobbyId, uint32_t playerId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_lobbies.find(lobbyId);
    if (it == m_lobbies.end()) {
        return false;
    }
    
    it->second.playerIds.push_back(playerId);
    it->second.currentPlayers++;
    m_playerLobby[playerId] = lobbyId;
    
    return true;
}

bool LobbyHandler::leaveLobby(uint32_t playerId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto playerIt = m_playerLobby.find(playerId);
    if (playerIt == m_playerLobby.end()) {
        return false;
    }
    
    uint32_t lobbyId = playerIt->second;
    m_playerLobby.erase(playerIt);
    
    auto lobbyIt = m_lobbies.find(lobbyId);
    if (lobbyIt != m_lobbies.end()) {
        auto& players = lobbyIt->second.playerIds;
        players.erase(std::remove(players.begin(), players.end(), playerId), players.end());
        lobbyIt->second.currentPlayers--;
        
        // If host left, either transfer host or destroy lobby
        if (lobbyIt->second.hostId == playerId) {
            if (players.empty()) {
                m_lobbies.erase(lobbyIt);
            } else {
                lobbyIt->second.hostId = players[0];
            }
        }
    }
    
    return true;
}

void LobbyHandler::destroyLobby(uint32_t lobbyId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_lobbies.find(lobbyId);
    if (it != m_lobbies.end()) {
        for (uint32_t playerId : it->second.playerIds) {
            m_playerLobby.erase(playerId);
        }
        m_lobbies.erase(it);
    }
}

LobbyInfo* LobbyHandler::getLobby(uint32_t lobbyId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto it = m_lobbies.find(lobbyId);
    if (it != m_lobbies.end()) {
        return &it->second;
    }
    return nullptr;
}

LobbyInfo* LobbyHandler::getPlayerLobby(uint32_t playerId) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    auto playerIt = m_playerLobby.find(playerId);
    if (playerIt == m_playerLobby.end()) {
        return nullptr;
    }
    
    auto lobbyIt = m_lobbies.find(playerIt->second);
    if (lobbyIt != m_lobbies.end()) {
        return &lobbyIt->second;
    }
    return nullptr;
}

std::vector<LobbyInfo> LobbyHandler::getPublicLobbies() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::vector<LobbyInfo> result;
    for (const auto& pair : m_lobbies) {
        if (!pair.second.isPrivate) {
            result.push_back(pair.second);
        }
    }
    return result;
}

void LobbyHandler::broadcastToLobby(uint32_t lobbyId, const network::Packet& packet) {
    // TODO: This needs access to server sessions
    // For now, this is a placeholder
    (void)lobbyId;
    (void)packet;
}

} // namespace protocol
} // namespace ds2
