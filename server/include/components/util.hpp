#pragma once

#include "blaze/component.hpp"
#include "blaze/types.hpp"
#include "network/client_connection.hpp"

namespace ds2::components {

using network::ClientConnection;

/**
 * Util Component
 * 
 * Handles utility functions like ping, configuration, and telemetry.
 * 
 * Commands:
 *   ping (0x01)              - Keep-alive ping
 *   preAuth (0x07)           - Pre-authentication config
 *   postAuth (0x08)          - Post-authentication config
 *   fetchClientConfig (0x0B) - Get client configuration
 */
class Util : public blaze::Component {
public:
    Util();
    
    std::unique_ptr<blaze::Packet> handlePacket(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    ) override;
    
private:
    std::unique_ptr<blaze::Packet> handlePing(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    );
    
    std::unique_ptr<blaze::Packet> handlePreAuth(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    );
    
    std::unique_ptr<blaze::Packet> handlePostAuth(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    );
    
    std::unique_ptr<blaze::Packet> handleFetchClientConfig(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    );
};

} // namespace ds2::components
