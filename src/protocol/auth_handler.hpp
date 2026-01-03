#pragma once

#include <memory>
#include "network/packet.hpp"

namespace ds2 {

class Session;

namespace protocol {

/**
 * Authentication handler
 * Handles player login and session validation
 */
class AuthHandler {
public:
    /**
     * Handle authentication request
     */
    static void handleAuthRequest(std::shared_ptr<Session> session, const network::Packet& packet);
    
    /**
     * Handle challenge response
     */
    static void handleChallengeResponse(std::shared_ptr<Session> session, const network::Packet& packet);
    
    /**
     * Send authentication challenge
     */
    static void sendChallenge(std::shared_ptr<Session> session);
    
    /**
     * Send authentication result
     */
    static void sendAuthResult(std::shared_ptr<Session> session, bool success, const std::string& message = "");
    
    /**
     * Register handlers with packet dispatcher
     */
    static void registerHandlers();
    
private:
    /**
     * Validate player credentials
     * In a real implementation, this would check against a database
     */
    static bool validateCredentials(const std::string& username, const std::string& authToken);
    
    /**
     * Generate a session token for authenticated player
     */
    static std::string generateSessionToken();
};

} // namespace protocol
} // namespace ds2
