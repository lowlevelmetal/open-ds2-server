#pragma once

#include "blaze/component.hpp"
#include "blaze/types.hpp"
#include "network/client_connection.hpp"
#include <string>
#include <map>
#include <mutex>

namespace ds2::components {

using network::ClientConnection;

/**
 * Authentication Component
 * 
 * Handles player authentication and session management.
 * 
 * Commands:
 *   login (0x01)          - Email/password login
 *   silentLogin (0x03)    - Token-based login
 *   logout (0x04)         - End session
 *   getAuthToken (0x06)   - Get auth token
 *   expressLogin (0x14)   - Quick login
 *   originLogin (0x1C)    - Origin platform login
 */
class Authentication : public blaze::Component {
public:
    Authentication();
    
    std::unique_ptr<blaze::Packet> handlePacket(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    ) override;
    
private:
    // Command handlers
    std::unique_ptr<blaze::Packet> handleLogin(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    );
    
    std::unique_ptr<blaze::Packet> handleSilentLogin(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    );
    
    std::unique_ptr<blaze::Packet> handleLogout(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    );
    
    std::unique_ptr<blaze::Packet> handleOriginLogin(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    );
    
    // Generate session for client
    uint64_t generateSessionId();
    std::string generateAuthToken();
    
    // Session storage
    std::map<uint64_t, std::weak_ptr<network::ClientConnection>> m_sessions;
    std::mutex m_sessionMutex;
    uint64_t m_nextSessionId = 1000;
};

} // namespace ds2::components
