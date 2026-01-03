#include "auth_handler.hpp"
#include "core/session.hpp"
#include "network/packet_handler.hpp"
#include "utils/buffer.hpp"
#include "utils/crypto.hpp"
#include "utils/logger.hpp"

namespace ds2 {
namespace protocol {

void AuthHandler::registerHandlers() {
    REGISTER_PACKET_HANDLER(AuthRequest, handleAuthRequest);
    REGISTER_PACKET_HANDLER(AuthChallengeResp, handleChallengeResponse);
    LOG_INFO("Authentication handlers registered");
}

void AuthHandler::handleAuthRequest(std::shared_ptr<Session> session, const network::Packet& packet) {
    LOG_DEBUG("Processing auth request from " + session->getAddress());
    
    if (session->getState() != SessionState::Connected) {
        LOG_WARN("Auth request from non-connected session");
        return;
    }
    
    session->setState(SessionState::Authenticating);
    
    try {
        BufferReader reader(packet.data);
        
        // Read protocol version
        uint8_t version = reader.readU8();
        LOG_DEBUG("Client protocol version: " + std::to_string(version));
        
        // Read username
        std::string username = reader.readLString();
        LOG_DEBUG("Auth request from user: " + username);
        
        // Read auth token (could be EA account token, etc.)
        std::string authToken = reader.readLString();
        
        // Store username
        session->setPlayerName(username);
        
        // Send challenge
        sendChallenge(session);
        
    } catch (const std::exception& e) {
        LOG_ERROR("Error parsing auth request: " + std::string(e.what()));
        sendAuthResult(session, false, "Invalid request format");
    }
}

void AuthHandler::handleChallengeResponse(std::shared_ptr<Session> session, const network::Packet& packet) {
    LOG_DEBUG("Processing challenge response from " + session->getAddress());
    
    if (session->getState() != SessionState::Authenticating) {
        LOG_WARN("Challenge response from non-authenticating session");
        return;
    }
    
    try {
        BufferReader reader(packet.data);
        
        // Read challenge response
        auto response = reader.readBytes(32);
        
        // TODO: Verify challenge response
        // For now, accept all responses (open server)
        
        // Generate player ID
        static uint32_t nextPlayerId = 1000;
        session->setPlayerId(nextPlayerId++);
        
        session->setState(SessionState::Authenticated);
        sendAuthResult(session, true);
        
        LOG_INFO("Player authenticated: " + session->getPlayerName() + 
                 " (ID: " + std::to_string(session->getPlayerId()) + ")");
        
    } catch (const std::exception& e) {
        LOG_ERROR("Error parsing challenge response: " + std::string(e.what()));
        sendAuthResult(session, false, "Invalid response");
    }
}

void AuthHandler::sendChallenge(std::shared_ptr<Session> session) {
    network::Packet packet(network::PacketType::AuthChallenge);
    
    BufferWriter writer;
    
    // Generate random challenge
    auto challenge = Crypto::randomBytes(32);
    writer.writeBytes(challenge);
    
    // Add server timestamp
    writer.writeU64(static_cast<uint64_t>(std::time(nullptr)));
    
    packet.data = writer.take();
    session->sendPacket(packet);
    
    LOG_DEBUG("Sent auth challenge to " + session->getAddress());
}

void AuthHandler::sendAuthResult(std::shared_ptr<Session> session, bool success, const std::string& message) {
    network::Packet packet(network::PacketType::AuthResponse);
    
    BufferWriter writer;
    writer.writeU8(success ? 1 : 0);
    writer.writeU32(session->getPlayerId());
    writer.writeLString(message.empty() ? (success ? "OK" : "Authentication failed") : message);
    
    // If successful, include session token
    if (success) {
        std::string token = generateSessionToken();
        writer.writeLString(token);
    }
    
    packet.data = writer.take();
    session->sendPacket(packet);
    
    if (!success) {
        session->disconnect(message);
    }
}

bool AuthHandler::validateCredentials(const std::string& username, const std::string& authToken) {
    // Open server - accept all credentials
    // In a real implementation, you would:
    // 1. Check against a database
    // 2. Verify EA account tokens if applicable
    // 3. Check ban lists
    
    (void)username;
    (void)authToken;
    
    return true;
}

std::string AuthHandler::generateSessionToken() {
    auto bytes = Crypto::randomBytes(16);
    return Crypto::toHex(bytes);
}

} // namespace protocol
} // namespace ds2
