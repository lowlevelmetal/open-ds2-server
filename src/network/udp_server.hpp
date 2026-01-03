#pragma once

#include <string>
#include <cstdint>
#include <functional>
#include <vector>

#include "tcp_server.hpp"

namespace ds2 {
namespace network {

struct UdpPacket {
    std::vector<uint8_t> data;
    sockaddr_in from;
    
    std::string getAddress() const {
        char addr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &from.sin_addr, addr, INET_ADDRSTRLEN);
        return std::string(addr) + ":" + std::to_string(ntohs(from.sin_port));
    }
};

/**
 * UDP Server for game traffic
 */
class UdpServer {
public:
    UdpServer();
    ~UdpServer();
    
    // Disable copy
    UdpServer(const UdpServer&) = delete;
    UdpServer& operator=(const UdpServer&) = delete;
    
    /**
     * Bind to an address and port
     */
    bool bind(const std::string& address, uint16_t port);
    
    /**
     * Receive a packet (non-blocking)
     * @return true if a packet was received
     */
    bool receive(UdpPacket& packet);
    
    /**
     * Send a packet to an address
     */
    bool send(const uint8_t* data, size_t length, const sockaddr_in& to);
    
    /**
     * Send a packet to an address string (ip:port)
     */
    bool send(const uint8_t* data, size_t length, const std::string& address, uint16_t port);
    
    /**
     * Close the socket
     */
    void close();
    
    /**
     * Check if socket is valid
     */
    bool isValid() const { return m_socket != INVALID_SOCKET_VALUE; }
    
private:
    socket_t m_socket{INVALID_SOCKET_VALUE};
    sockaddr_in m_addr{};
};

} // namespace network
} // namespace ds2
