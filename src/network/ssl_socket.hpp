#pragma once

#include "tcp_server.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <string>
#include <memory>

namespace ds2 {
namespace network {

/**
 * SSL Context wrapper for managing SSL/TLS configuration
 */
class SslContext {
public:
    SslContext();
    ~SslContext();
    
    // Disable copy
    SslContext(const SslContext&) = delete;
    SslContext& operator=(const SslContext&) = delete;
    
    /**
     * Initialize SSL context for server mode
     * @param certFile Path to certificate file (PEM format)
     * @param keyFile Path to private key file (PEM format)
     * @return true on success
     */
    bool initialize(const std::string& certFile, const std::string& keyFile);
    
    /**
     * Get the underlying SSL_CTX pointer
     */
    SSL_CTX* get() const { return m_ctx; }
    
    /**
     * Check if context is valid
     */
    bool isValid() const { return m_ctx != nullptr; }
    
    /**
     * Get last error string
     */
    static std::string getLastError();
    
private:
    SSL_CTX* m_ctx = nullptr;
};

/**
 * SSL Socket wrapper that provides encrypted communication
 * Wraps an existing TCP socket with SSL/TLS
 */
class SslSocket {
public:
    SslSocket();
    ~SslSocket();
    
    // Disable copy
    SslSocket(const SslSocket&) = delete;
    SslSocket& operator=(const SslSocket&) = delete;
    
    // Enable move
    SslSocket(SslSocket&& other) noexcept;
    SslSocket& operator=(SslSocket&& other) noexcept;
    
    /**
     * Accept an SSL connection from an accepted socket
     * @param socket Raw socket from accept()
     * @param ctx SSL context to use
     * @return true if SSL handshake succeeded
     */
    bool accept(socket_t socket, SslContext& ctx);
    
    /**
     * Send data over SSL
     * @return Number of bytes sent, or -1 on error
     */
    int send(const uint8_t* data, size_t length);
    
    /**
     * Receive data over SSL (non-blocking)
     * @return Number of bytes received, 0 if no data, -1 on error/disconnect
     */
    int receive(uint8_t* buffer, size_t maxLength);
    
    /**
     * Close the SSL connection and underlying socket
     */
    void close();
    
    /**
     * Check if socket is valid
     */
    bool isValid() const { return m_ssl != nullptr && m_socket != INVALID_SOCKET_VALUE; }
    
    /**
     * Get the underlying socket
     */
    socket_t getSocket() const { return m_socket; }
    
    /**
     * Get remote address as string
     */
    std::string getRemoteAddress() const;
    
    /**
     * Get remote port
     */
    uint16_t getRemotePort() const;

private:
    SSL* m_ssl = nullptr;
    socket_t m_socket = INVALID_SOCKET_VALUE;
    sockaddr_in m_remoteAddr{};
    
    bool setNonBlocking(bool nonBlocking);
};

/**
 * SSL Server that listens for incoming SSL connections
 */
class SslServer {
public:
    SslServer();
    ~SslServer();
    
    /**
     * Initialize the SSL server with certificate and key
     * @param certFile Path to certificate file
     * @param keyFile Path to private key file
     * @return true on success
     */
    bool initialize(const std::string& certFile, const std::string& keyFile);
    
    /**
     * Start listening on a port
     * @param port Port to listen on
     * @param backlog Connection backlog
     * @return true on success
     */
    bool listen(uint16_t port, int backlog = 10);
    
    /**
     * Accept an incoming SSL connection (non-blocking)
     * @return Unique pointer to SslSocket, or nullptr if no connection
     */
    std::unique_ptr<SslSocket> accept();
    
    /**
     * Stop the server
     */
    void stop();
    
    /**
     * Check if server is running
     */
    bool isRunning() const { return m_listenSocket != INVALID_SOCKET_VALUE; }

private:
    SslContext m_ctx;
    socket_t m_listenSocket = INVALID_SOCKET_VALUE;
};

/**
 * Initialize OpenSSL library (call once at startup)
 */
void initializeOpenSSL();

/**
 * Cleanup OpenSSL library (call once at shutdown)
 */
void cleanupOpenSSL();

} // namespace network
} // namespace ds2
