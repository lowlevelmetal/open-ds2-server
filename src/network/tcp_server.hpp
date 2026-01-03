#pragma once

#include <string>
#include <memory>
#include <cstdint>

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
    using socket_t = SOCKET;
    constexpr socket_t INVALID_SOCKET_VALUE = INVALID_SOCKET;
#else
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <cerrno>
    using socket_t = int;
    constexpr socket_t INVALID_SOCKET_VALUE = -1;
#endif

namespace ds2 {
namespace network {

/**
 * TCP Socket wrapper
 */
class TcpSocket {
public:
    TcpSocket();
    explicit TcpSocket(socket_t socket);  // Gets peer address automatically
    explicit TcpSocket(socket_t socket, const sockaddr_in& addr);
    ~TcpSocket();
    
    // Disable copy
    TcpSocket(const TcpSocket&) = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;
    
    // Enable move
    TcpSocket(TcpSocket&& other) noexcept;
    TcpSocket& operator=(TcpSocket&& other) noexcept;
    
    /**
     * Connect to a remote host
     */
    bool connect(const std::string& host, uint16_t port);
    
    /**
     * Send data
     * @return Number of bytes sent, or -1 on error
     */
    int send(const uint8_t* data, size_t length);
    
    /**
     * Receive data (non-blocking)
     * @return Number of bytes received, 0 if no data, -1 on error/disconnect
     */
    int receive(uint8_t* buffer, size_t maxLength);
    
    /**
     * Close the socket
     */
    void close();
    
    /**
     * Check if socket is valid
     */
    bool isValid() const { return m_socket != INVALID_SOCKET_VALUE; }
    
    /**
     * Set non-blocking mode
     */
    bool setNonBlocking(bool nonBlocking);
    
    /**
     * Set TCP_NODELAY option
     */
    bool setNoDelay(bool noDelay);
    
    /**
     * Get remote address string
     */
    std::string getRemoteAddress() const;
    
    /**
     * Get remote port
     */
    uint16_t getRemotePort() const;
    
private:
    socket_t m_socket{INVALID_SOCKET_VALUE};
    sockaddr_in m_remoteAddr{};
};

/**
 * TCP Server
 */
class TcpServer {
public:
    TcpServer();
    ~TcpServer();
    
    // Disable copy
    TcpServer(const TcpServer&) = delete;
    TcpServer& operator=(const TcpServer&) = delete;
    
    /**
     * Bind to an address and port
     */
    bool bind(const std::string& address, uint16_t port);
    
    /**
     * Start listening for connections
     */
    bool listen(int backlog = 10);
    
    /**
     * Accept a new connection (blocking)
     */
    std::unique_ptr<TcpSocket> accept();
    
    /**
     * Close the server socket
     */
    void close();
    
    /**
     * Check if server is valid
     */
    bool isValid() const { return m_socket != INVALID_SOCKET_VALUE; }
    
private:
    socket_t m_socket{INVALID_SOCKET_VALUE};
    sockaddr_in m_addr{};
};

/**
 * Initialize networking (Windows only)
 */
bool initializeNetworking();

/**
 * Cleanup networking (Windows only)
 */
void cleanupNetworking();

} // namespace network
} // namespace ds2
