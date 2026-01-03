#include "blaze_server.hpp"
#include "blaze_codec.hpp"
#include "components.hpp"
#include "core/session.hpp"
#include "network/tcp_server.hpp"
#include "network/ssl_socket.hpp"
#include "utils/logger.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

namespace ds2 {
namespace blaze {

// =============================================================================
// ClientConnection Implementation  
// =============================================================================

int ClientConnection::send(const uint8_t* data, size_t length) {
    if (isSSL) {
        auto& ssl = std::get<std::unique_ptr<network::SslSocket>>(socket);
        return ssl ? ssl->send(data, length) : -1;
    } else {
        auto& tcp = std::get<std::unique_ptr<network::TcpSocket>>(socket);
        return tcp ? tcp->send(data, length) : -1;
    }
}

int ClientConnection::receive(uint8_t* buffer, size_t maxLength) {
    if (isSSL) {
        auto& ssl = std::get<std::unique_ptr<network::SslSocket>>(socket);
        return ssl ? ssl->receive(buffer, maxLength) : -1;
    } else {
        auto& tcp = std::get<std::unique_ptr<network::TcpSocket>>(socket);
        return tcp ? tcp->receive(buffer, maxLength) : -1;
    }
}

void ClientConnection::close() {
    if (isSSL) {
        auto& ssl = std::get<std::unique_ptr<network::SslSocket>>(socket);
        if (ssl) ssl->close();
    } else {
        auto& tcp = std::get<std::unique_ptr<network::TcpSocket>>(socket);
        if (tcp) tcp->close();
    }
}

bool ClientConnection::isValid() const {
    if (isSSL) {
        auto& ssl = std::get<std::unique_ptr<network::SslSocket>>(socket);
        return ssl && ssl->isValid();
    } else {
        auto& tcp = std::get<std::unique_ptr<network::TcpSocket>>(socket);
        return tcp && tcp->isValid();
    }
}

std::string ClientConnection::getAddress() const {
    if (isSSL) {
        auto& ssl = std::get<std::unique_ptr<network::SslSocket>>(socket);
        return ssl ? ssl->getRemoteAddress() : "unknown";
    } else {
        auto& tcp = std::get<std::unique_ptr<network::TcpSocket>>(socket);
        return tcp ? tcp->getRemoteAddress() : "unknown";
    }
}

// =============================================================================
// BlazeServer Implementation
// =============================================================================

BlazeServer::BlazeServer() = default;

BlazeServer::~BlazeServer() {
    stop();
}

void BlazeServer::setSSLFiles(const std::string& certFile, const std::string& keyFile) {
    m_certFile = certFile;
    m_keyFile = keyFile;
}

bool BlazeServer::initialize(uint16_t redirectorPort, uint16_t gamePort, bool useSSL) {
    m_redirectorPort = redirectorPort;
    m_gamePort = gamePort;
    m_useSSL = useSSL;
    
    // Initialize SSL for redirector if enabled
    if (m_useSSL) {
        if (m_certFile.empty() || m_keyFile.empty()) {
            LOG_WARN("SSL enabled but no certificate/key files specified");
            LOG_WARN("Use setSSLFiles() or set ssl_cert/ssl_key in config");
            LOG_WARN("Falling back to non-SSL mode for redirector");
            m_useSSL = false;
        } else {
            m_sslServer = std::make_unique<network::SslServer>();
            if (!m_sslServer->initialize(m_certFile, m_keyFile)) {
                LOG_ERROR("Failed to initialize SSL server");
                LOG_WARN("Falling back to non-SSL mode for redirector");
                m_useSSL = false;
                m_sslServer.reset();
            }
        }
    }
    
    // Create redirector socket (non-SSL or fallback)
    if (!m_useSSL) {
        m_redirectorSocket = socket(AF_INET, SOCK_STREAM, 0);
        if (m_redirectorSocket < 0) {
            LOG_ERROR("Failed to create redirector socket");
            return false;
        }
        
        int opt = 1;
        setsockopt(m_redirectorSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        sockaddr_in redirectorAddr{};
        redirectorAddr.sin_family = AF_INET;
        redirectorAddr.sin_addr.s_addr = INADDR_ANY;
        redirectorAddr.sin_port = htons(m_redirectorPort);
        
        if (bind(m_redirectorSocket, (sockaddr*)&redirectorAddr, sizeof(redirectorAddr)) < 0) {
            LOG_ERROR("Failed to bind redirector socket to port " + std::to_string(m_redirectorPort));
            ::close(m_redirectorSocket);
            m_redirectorSocket = -1;
            return false;
        }
    }
    
    // Create game server socket (always plain TCP)
    m_gameSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (m_gameSocket < 0) {
        LOG_ERROR("Failed to create game server socket");
        if (m_redirectorSocket >= 0) {
            ::close(m_redirectorSocket);
            m_redirectorSocket = -1;
        }
        return false;
    }
    
    int opt = 1;
    setsockopt(m_gameSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    sockaddr_in gameAddr{};
    gameAddr.sin_family = AF_INET;
    gameAddr.sin_addr.s_addr = INADDR_ANY;
    gameAddr.sin_port = htons(m_gamePort);
    
    if (bind(m_gameSocket, (sockaddr*)&gameAddr, sizeof(gameAddr)) < 0) {
        LOG_ERROR("Failed to bind game server socket to port " + std::to_string(m_gamePort));
        if (m_redirectorSocket >= 0) {
            ::close(m_redirectorSocket);
            m_redirectorSocket = -1;
        }
        ::close(m_gameSocket);
        m_gameSocket = -1;
        return false;
    }
    
    LOG_INFO("Blaze server initialized");
    LOG_INFO("  Redirector port: " + std::to_string(m_redirectorPort) + 
             (m_useSSL ? " (SSL)" : " (plain)"));
    LOG_INFO("  Game server port: " + std::to_string(m_gamePort));
    
    return true;
}

bool BlazeServer::start() {
    if (m_running) {
        return true;
    }
    
    // Start listening on SSL redirector or plain redirector
    if (m_useSSL) {
        if (!m_sslServer->listen(m_redirectorPort)) {
            LOG_ERROR("Failed to listen on SSL redirector socket");
            return false;
        }
    } else {
        if (listen(m_redirectorSocket, 16) < 0) {
            LOG_ERROR("Failed to listen on redirector socket");
            return false;
        }
    }
    
    // Start listening on game server (always plain TCP)
    if (listen(m_gameSocket, 64) < 0) {
        LOG_ERROR("Failed to listen on game socket");
        return false;
    }
    
    m_running = true;
    
    // Start accept threads
    if (m_useSSL) {
        m_acceptThreads.emplace_back(&BlazeServer::acceptLoopSSL, this);
    } else {
        m_acceptThreads.emplace_back(&BlazeServer::acceptLoopTCP, this, m_redirectorSocket, true);
    }
    m_acceptThreads.emplace_back(&BlazeServer::acceptLoopTCP, this, m_gameSocket, false);
    
    LOG_INFO("Blaze server started");
    
    return true;
}

void BlazeServer::stop() {
    if (!m_running) {
        return;
    }
    
    m_running = false;
    
    // Close SSL server
    if (m_sslServer) {
        m_sslServer->stop();
    }
    
    // Close server sockets to unblock accept()
    if (m_redirectorSocket >= 0) {
        shutdown(m_redirectorSocket, SHUT_RDWR);
        ::close(m_redirectorSocket);
        m_redirectorSocket = -1;
    }
    
    if (m_gameSocket >= 0) {
        shutdown(m_gameSocket, SHUT_RDWR);
        ::close(m_gameSocket);
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

void BlazeServer::acceptLoopSSL() {
    LOG_DEBUG("SSL Redirector accept loop started");
    
    while (m_running) {
        auto sslSocket = m_sslServer->accept();
        if (!sslSocket) {
            // No pending connection, small delay
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
            continue;
        }
        
        LOG_INFO("SSL Redirector connection from " + sslSocket->getRemoteAddress() + 
                 ":" + std::to_string(sslSocket->getRemotePort()));
        
        // Create session with SSL socket
        // For now, we need to wrap it - Session needs TcpSocket interface
        // TODO: Refactor Session to support both socket types
        // For now, log that we got the connection but can't process it yet
        LOG_WARN("SSL connection established but Session doesn't support SSL sockets yet");
        LOG_WARN("The client connected successfully via SSL - protocol is working!");
        
        // We could implement a simple response here for testing
        // For now just close after a delay
        std::this_thread::sleep_for(std::chrono::seconds(1));
        sslSocket->close();
    }
}

void BlazeServer::acceptLoopTCP(int serverSocket, bool isRedirector) {
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
