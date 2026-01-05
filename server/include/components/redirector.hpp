#pragma once

#include "blaze/component.hpp"
#include "blaze/types.hpp"
#include "network/client_connection.hpp"
#include <string>

namespace ds2::components {

using network::ClientConnection;

/**
 * Redirector Component
 * 
 * Handles server redirection. This is the first component the client
 * contacts on port 42127 to get the main Blaze server address.
 * 
 * Commands:
 *   getServerInstance (0x01) - Returns the Blaze server IP/port
 */
class Redirector : public blaze::Component {
public:
    Redirector();
    
    // Set the Blaze server address to redirect clients to
    void setBlazeServerAddress(const std::string& host, uint16_t port);
    
    std::unique_ptr<blaze::Packet> handlePacket(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    ) override;
    
private:
    std::unique_ptr<blaze::Packet> handleGetServerInstance(
        const blaze::Packet& request,
        std::shared_ptr<ClientConnection> client
    );
    
    std::string m_blazeHost;
    uint16_t m_blazePort;
};

} // namespace ds2::components
