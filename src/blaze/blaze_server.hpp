#pragma once

#include "blaze_types.hpp"
#include "network/ssl_socket.hpp"
#include <memory>
#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <map>
#include <mutex>
#include <variant>

namespace ds2 {

class Session;

namespace blaze {

/**
 * SSL Client connection holder
 * Wraps either a regular TCP socket or SSL socket
 */
struct ClientConnection {
    std::variant<std::unique_ptr<network::TcpSocket>, 
                 std::unique_ptr<network::SslSocket>> socket;
    bool isSSL = false;
    
    int send(const uint8_t* data, size_t length);
    int receive(uint8_t* buffer, size_t maxLength);
    void close();
    bool isValid() const;
    std::string getAddress() const;
};

/**
 * Blaze Server
 * 
 * Dedicated server for handling Blaze protocol connections.
 * This is the main entry point for clients connecting via the Blaze backend.
 * 
 * The server handles:
 * - Redirector service (initial connection, points to game server) - SSL enabled
 * - Main game server (authentication, game management, etc.) - Plain TCP
 */
class BlazeServer {
public:
    BlazeServer();
    ~BlazeServer();
    
    // Disable copy
    BlazeServer(const BlazeServer&) = delete;
    BlazeServer& operator=(const BlazeServer&) = delete;
    
    /**
     * Initialize the Blaze server
     * @param redirectorPort Port for redirector service (default: 42127)
     * @param gamePort Port for main game server (default: 10041)
     * @param useSSL Whether to use SSL/TLS for redirector (default: true)
     * @return true on success
     */
    bool initialize(uint16_t redirectorPort = 42127,
                   uint16_t gamePort = 10041,
                   bool useSSL = true);
    
    /**
     * Set SSL certificate and key files
     * Must be called before initialize() if SSL is enabled
     * @param certFile Path to certificate file (PEM format)
     * @param keyFile Path to private key file (PEM format)
     */
    void setSSLFiles(const std::string& certFile, const std::string& keyFile);
    
    /**
     * Start accepting connections
     */
    bool start();
    
    /**
     * Stop the server
     */
    void stop();
    
    /**
     * Check if server is running
     */
    bool isRunning() const { return m_running; }
    
    /**
     * Process a Blaze packet from a session
     */
    void processPacket(std::shared_ptr<Session> session, const std::vector<uint8_t>& data);
    
    /**
     * Get number of connected clients
     */
    size_t getClientCount() const;
    
private:
    void acceptLoopTCP(int serverSocket, bool isRedirector);
    void acceptLoopSSL();
    void clientLoop(std::shared_ptr<Session> session);
    
    std::atomic<bool> m_running{false};
    bool m_useSSL{true};
    
    int m_redirectorSocket{-1};  // Used when SSL is disabled
    int m_gameSocket{-1};
    
    std::unique_ptr<network::SslServer> m_sslServer;  // SSL redirector
    
    std::string m_certFile;
    std::string m_keyFile;
    
    uint16_t m_redirectorPort{42127};
    uint16_t m_gamePort{10041};
    
    std::vector<std::thread> m_acceptThreads;
    std::vector<std::thread> m_clientThreads;
    
    std::map<uint64_t, std::shared_ptr<Session>> m_sessions;
    mutable std::mutex m_sessionMutex;
    
    uint64_t m_nextSessionId{1};
};

} // namespace blaze
} // namespace ds2
