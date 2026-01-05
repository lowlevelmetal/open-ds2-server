#include "server.hpp"
#include "blaze/component.hpp"
#include "network/client_connection.hpp"
#include "components/redirector.hpp"
#include "components/authentication.hpp"
#include "components/util.hpp"
#include "components/game_manager.hpp"
#include "utils/logger.hpp"

namespace ds2 {

Server::Server()
    : m_running(false)
{
}

Server::~Server() {
    stop();
}

bool Server::init(const blaze::ServerConfig& config) {
    m_config = config;
    
    LOG_INFO("Initializing Dead Space 2 Server Emulator");
    LOG_INFO("  Redirector: {}:{}", config.redirector_host, config.redirector_port);
    LOG_INFO("  Blaze:      {}:{}", config.blaze_host, config.blaze_port);
    LOG_INFO("  QoS:        {}:{}", config.qos_host, config.qos_port);
    
    // Register components
    setupComponents();
    
    // Create servers
    m_redirectorServer = std::make_shared<network::SSLServer>(
        m_io_context, config.redirector_host, config.redirector_port);
    
    m_blazeServer = std::make_shared<network::SSLServer>(
        m_io_context, config.blaze_host, config.blaze_port);
    
    m_qosServer = std::make_shared<network::QoSServer>(
        m_io_context, config.qos_host, config.qos_port);
    
    // Configure SSL
    if (!m_redirectorServer->configureSsl(config.ssl_cert_path, config.ssl_key_path)) {
        LOG_ERROR("Failed to configure SSL for redirector");
        return false;
    }
    
    if (!m_blazeServer->configureSsl(config.ssl_cert_path, config.ssl_key_path)) {
        LOG_ERROR("Failed to configure SSL for blaze server");
        return false;
    }
    
    // Set connection handlers
    m_redirectorServer->setConnectionHandler(
        [this](auto socket) { handleRedirectorConnection(socket); });
    
    m_blazeServer->setConnectionHandler(
        [this](auto socket) { handleBlazeConnection(socket); });
    
    LOG_INFO("Server initialized successfully");
    return true;
}

void Server::setupComponents() {
    auto& registry = blaze::ComponentRegistry::instance();
    
    // Create and configure Redirector
    auto redirector = std::make_shared<components::Redirector>();
    redirector->setBlazeServerAddress(m_config.blaze_host, m_config.blaze_port);
    registry.registerComponent(redirector);
    
    // Create Authentication
    registry.registerComponent(std::make_shared<components::Authentication>());
    
    // Create Util
    registry.registerComponent(std::make_shared<components::Util>());
    
    // Create GameManager
    registry.registerComponent(std::make_shared<components::GameManager>());
    
    LOG_INFO("Components registered");
}

void Server::start() {
    if (m_running) return;
    
    m_running = true;
    
    // Start all servers
    m_redirectorServer->start();
    m_blazeServer->start();
    m_qosServer->start();
    
    LOG_INFO("All servers started");
}

void Server::stop() {
    if (!m_running) return;
    
    LOG_INFO("Stopping servers...");
    
    m_running = false;
    m_io_context.stop();
    
    // Stop servers
    if (m_redirectorServer) m_redirectorServer->stop();
    if (m_blazeServer) m_blazeServer->stop();
    if (m_qosServer) m_qosServer->stop();
    
    // Wait for worker threads
    for (auto& thread : m_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
    m_threads.clear();
    
    LOG_INFO("Servers stopped");
}

void Server::run() {
    // Start worker threads
    unsigned int numThreads = std::thread::hardware_concurrency();
    if (numThreads < 2) numThreads = 2;
    
    LOG_INFO("Starting {} worker threads", numThreads);
    
    for (unsigned int i = 0; i < numThreads; i++) {
        m_threads.emplace_back([this]() {
            m_io_context.run();
        });
    }
    
    // Wait for threads
    for (auto& thread : m_threads) {
        if (thread.joinable()) {
            thread.join();
        }
    }
}

void Server::handleRedirectorConnection(
    std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> socket
) {
    uint64_t connId = m_nextConnectionId++;
    
    auto client = std::make_shared<network::ClientConnection>(socket, connId);
    
    client->setPacketHandler([this](auto client, auto packet) {
        if (!packet) return;
        
        auto& registry = blaze::ComponentRegistry::instance();
        auto response = registry.routePacket(*packet, client);
        
        if (response) {
            client->sendPacket(std::move(response));
        }
    });
    
    client->setDisconnectHandler([](auto client) {
        LOG_INFO("Redirector client {} disconnected", client->getId());
    });
    
    client->start();
}

void Server::handleBlazeConnection(
    std::shared_ptr<asio::ssl::stream<asio::ip::tcp::socket>> socket
) {
    uint64_t connId = m_nextConnectionId++;
    
    auto client = std::make_shared<network::ClientConnection>(socket, connId);
    
    client->setPacketHandler([this](auto client, auto packet) {
        if (!packet) return;
        
        auto& registry = blaze::ComponentRegistry::instance();
        auto response = registry.routePacket(*packet, client);
        
        if (response) {
            client->sendPacket(std::move(response));
        }
    });
    
    client->setDisconnectHandler([](auto client) {
        LOG_INFO("Blaze client {} disconnected", client->getId());
    });
    
    client->start();
}

} // namespace ds2
