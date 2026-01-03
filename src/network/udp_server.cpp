#include "udp_server.hpp"
#include "utils/logger.hpp"

#include <cstring>

namespace ds2 {
namespace network {

UdpServer::UdpServer() {
    initializeNetworking();
}

UdpServer::~UdpServer() {
    close();
}

bool UdpServer::bind(const std::string& address, uint16_t port) {
    if (m_socket != INVALID_SOCKET_VALUE) {
        close();
    }
    
    m_socket = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (m_socket == INVALID_SOCKET_VALUE) {
        LOG_ERROR("Failed to create UDP socket");
        return false;
    }
    
    // Allow address reuse
    int opt = 1;
    setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, 
               reinterpret_cast<const char*>(&opt), sizeof(opt));
    
    // Set non-blocking
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(m_socket, FIONBIO, &mode);
#else
    int flags = fcntl(m_socket, F_GETFL, 0);
    fcntl(m_socket, F_SETFL, flags | O_NONBLOCK);
#endif
    
    // Setup address
    m_addr.sin_family = AF_INET;
    m_addr.sin_port = htons(port);
    
    if (address == "0.0.0.0" || address.empty()) {
        m_addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, address.c_str(), &m_addr.sin_addr);
    }
    
    // Bind
    if (::bind(m_socket, reinterpret_cast<sockaddr*>(&m_addr), sizeof(m_addr)) < 0) {
        LOG_ERROR("Failed to bind UDP socket to " + address + ":" + std::to_string(port));
        close();
        return false;
    }
    
    return true;
}

bool UdpServer::receive(UdpPacket& packet) {
    if (m_socket == INVALID_SOCKET_VALUE) {
        return false;
    }
    
    uint8_t buffer[65536];
    sockaddr_in from{};
    socklen_t fromLen = sizeof(from);
    
#ifdef _WIN32
    int received = ::recvfrom(m_socket, reinterpret_cast<char*>(buffer), sizeof(buffer), 0,
                              reinterpret_cast<sockaddr*>(&from), &fromLen);
    if (received == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            return false;
        }
        LOG_ERROR("UDP receive error: " + std::to_string(err));
        return false;
    }
#else
    ssize_t received = ::recvfrom(m_socket, buffer, sizeof(buffer), 0,
                                  reinterpret_cast<sockaddr*>(&from), &fromLen);
    if (received < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return false;
        }
        LOG_ERROR("UDP receive error: " + std::string(strerror(errno)));
        return false;
    }
#endif
    
    if (received == 0) {
        return false;
    }
    
    packet.data.assign(buffer, buffer + received);
    packet.from = from;
    
    return true;
}

bool UdpServer::send(const uint8_t* data, size_t length, const sockaddr_in& to) {
    if (m_socket == INVALID_SOCKET_VALUE) {
        return false;
    }
    
#ifdef _WIN32
    int sent = ::sendto(m_socket, reinterpret_cast<const char*>(data), static_cast<int>(length), 0,
                        reinterpret_cast<const sockaddr*>(&to), sizeof(to));
    return sent != SOCKET_ERROR;
#else
    ssize_t sent = ::sendto(m_socket, data, length, 0,
                            reinterpret_cast<const sockaddr*>(&to), sizeof(to));
    return sent >= 0;
#endif
}

bool UdpServer::send(const uint8_t* data, size_t length, const std::string& address, uint16_t port) {
    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    inet_pton(AF_INET, address.c_str(), &to.sin_addr);
    
    return send(data, length, to);
}

void UdpServer::close() {
    if (m_socket != INVALID_SOCKET_VALUE) {
#ifdef _WIN32
        ::closesocket(m_socket);
#else
        ::close(m_socket);
#endif
        m_socket = INVALID_SOCKET_VALUE;
    }
}

} // namespace network
} // namespace ds2
