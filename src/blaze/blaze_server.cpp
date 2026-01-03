#include "blaze_server.hpp"
#include "blaze_codec.hpp"
#include "components.hpp"
#include "core/session.hpp"
#include "network/tcp_server.hpp"
#include "utils/logger.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

namespace ds2 {
namespace blaze {

BlazeServer::BlazeServer() = default;

BlazeServer::~BlazeServer() {
    stop();
}

bool BlazeServer::initialize(uint16_t redirectorPort, uint16_t gamePort, bool useSSL) {
    (void)useSSL;  // TODO: Implement SSL support
    
    m_redirectorPort = redirectorPort;
    m_gamePort = gamePort;
    
    // Create redirector socket
    m_redirectorSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_redirectorSocket < 0) {
        LOG_ERROR("Failed to create redirector socket");
        return false;
    }
    
    // Create game server socket  
    m_gameSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_gameSocket < 0) {
        LOG_ERROR("Failed to create game server socket");
        close(m_redirectorSocket);
        return false;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(m_redirectorSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    setsockopt(m_gameSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Bind redirector socket
    sockaddr_in redirectorAddr{};
    redirectorAddr.sin_family = AF_INET;
    redirectorAddr.sin_addr.s_addr = INADDR_ANY;
    redirectorAddr.sin_port = htons(m_redirectorPort);
    
    if (bind(m_redirectorSocket, (sockaddr*)&redirectorAddr, sizeof(redirectorAddr)) < 0) {
        LOG_ERROR("Failed to bind redirector socket to port " + std::to_string(m_redirectorPort));
        close(m_redirectorSocket);
        close(m_gameSocket);
        return false;
    }
    
    // Bind game server socket
    sockaddr_in gameAddr{};
    gameAddr.sin_family = AF_INET;
    gameAddr.sin_addr.s_addr = INADDR_ANY;
    gameAddr.sin_port = htons(m_gamePort);
    
    if (bind(m_gameSocket, (sockaddr*)&gameAddr, sizeof(gameAddr)) < 0) {
        LOG_ERROR("Failed to bind game server socket to port " + std::to_string(m_gamePort));
        close(m_redirectorSocket);
        close(m_gameSocket);
        return false;
    }
    
    LOG_INFO("Blaze server initialized");
    LOG_INFO("  Redirector port: " + std::to_string(m_redirectorPort));
    LOG_INFO("  Game server port: " + std::to_string(m_gamePort));
    
    return true;
}

bool BlazeServer::start() {
    if (m_running) {
        return true;
    }
    
    // Start listening
    if (listen(m_redirectorSocket, 16) < 0) {
        LOG_ERROR("Failed to listen on redirector socket");
        return false;
    }
    
    if (listen(m_gameSocket, 64) < 0) {
        LOG_ERROR("Failed to listen on game socket");
        return false;
    }
    
    m_running = true;
    
    // Start accept threads
    m_acceptThreads.emplace_back(&BlazeServer::acceptLoop, this, m_redirectorSocket, true);
    m_acceptThreads.emplace_back(&BlazeServer::acceptLoop, this, m_gameSocket, false);
    
    LOG_INFO("Blaze server started");
    
    return true;
}

void BlazeServer::stop() {
    if (!m_running) {
        return;
    }
    
    m_running = false;
    
    // Close server sockets to unblock accept()
    if (m_redirectorSocket >= 0) {
        shutdown(m_redirectorSocket, SHUT_RDWR);
        close(m_redirectorSocket);
        m_redirectorSocket = -1;
    }
    
    if (m_gameSocket >= 0) {
        shutdown(m_gameSocket, SHUT_RDWR);
        close(m_gameSocket);
        m_gameSocket = -1;
    }
    
    // Wait for accept threads
    for (auto& thread : m_acceptThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    m_acceptThreads.clear();
    
    // Disconnect all clients
    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        for (auto& [id, session] : m_sessions) {
            session->disconnect("Server stopping");
        }
        m_sessions.clear();
    }
    
    // Wait for client threads
    for (auto& thread : m_clientThreads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    m_clientThreads.clear();
    
    LOG_INFO("Blaze server stopped");
}

void BlazeServer::acceptLoop(int serverSocket, bool isRedirector) {
    const char* serverType = isRedirector ? "Redirector" : "Game";
    LOG_DEBUG(std::string(serverType) + " accept loop started");
    
    while (m_running) {
        sockaddr_in clientAddr{};
        socklen_t addrLen = sizeof(clientAddr);
        
        int clientSocket = accept(serverSocket, (sockaddr*)&clientAddr, &addrLen);
        if (clientSocket < 0) {
            if (m_running) {
                LOG_ERROR(std::string(serverType) + " accept failed");
            }
            continue;
        }
        
        char addrStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &clientAddr.sin_addr, addrStr, sizeof(addrStr));
        LOG_INFO(std::string(serverType) + " connection from " + addrStr + 
                 ":" + std::to_string(ntohs(clientAddr.sin_port)));
        
        // Create TcpSocket wrapper
        auto tcpSocket = std::make_unique<network::TcpSocket>(clientSocket);
        
        // Create session
        auto session = std::make_shared<Session>(std::move(tcpSocket));
        
        // Store session
        uint64_t sessionId;
        {
            std::lock_guard<std::mutex> lock(m_sessionMutex);
            sessionId = m_nextSessionId++;
            m_sessions[sessionId] = session;
        }
        
        // Start client handler thread
        m_clientThreads.emplace_back(&BlazeServer::clientLoop, this, session);
    }
}

void BlazeServer::clientLoop(std::shared_ptr<Session> session) {
    LOG_DEBUG("Client handler started for " + session->getAddress());
    
    std::vector<uint8_t> buffer(8192);
    std::vector<uint8_t> accumulated;
    
    while (m_running && session->isConnected()) {
        // This is a simplified implementation - in production you'd use
        // non-blocking I/O or select()/poll()/epoll()
        
        // For now, just process incoming data
        session->processIncoming();
        
        // Small delay to prevent busy-waiting
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    LOG_DEBUG("Client handler ended for " + session->getAddress());
}

void BlazeServer::processPacket(std::shared_ptr<Session> session, const std::vector<uint8_t>& data) {
    Packet packet;
    if (BlazeCodec::decode(data.data(), data.size(), packet) == 0) {
        LOG_WARN("Failed to decode Blaze packet from " + session->getAddress());
        return;
    }
    
    // Route to handler
    BlazeRouter::getInstance().route(session, packet);
}

size_t BlazeServer::getClientCount() const {
    std::lock_guard<std::mutex> lock(m_sessionMutex);
    return m_sessions.size();
}

} // namespace blaze
} // namespace ds2
