#pragma once

#include "blaze_types.hpp"
#include <memory>
#include <vector>
#include <string>
#include <atomic>
#include <thread>
#include <map>
#include <mutex>

namespace ds2 {

class Session;

namespace blaze {

/**
 * Blaze Server
 * 
 * Dedicated server for handling Blaze protocol connections.
 * This is the main entry point for clients connecting via the Blaze backend.
 * 
 * The server handles:
 * - Redirector service (initial connection, points to game server)
 * - Main game server (authentication, game management, etc.)
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
     * @param useSSL Whether to use SSL/TLS (default: true for redirector)
     * @return true on success
     */
    bool initialize(uint16_t redirectorPort = 42127,
                   uint16_t gamePort = 10041,
                   bool useSSL = false);  // SSL disabled by default until implemented
    
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
    void acceptLoop(int serverSocket, bool isRedirector);
    void clientLoop(std::shared_ptr<Session> session);
    
    std::atomic<bool> m_running{false};
    
    int m_redirectorSocket{-1};
    int m_gameSocket{-1};
    
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
