/**
 * Open Dead Space 2 Server
 * 
 * An open source implementation of the Dead Space 2 multiplayer server.
 * This project aims to restore online functionality for Dead Space 2.
 */

#include <iostream>
#include <csignal>
#include <atomic>

#include "core/config.hpp"
#include "utils/logger.hpp"
#include "blaze/blaze_server.hpp"
#include "blaze/components.hpp"

std::atomic<bool> g_running{true};

void signalHandler(int signal) {
    if (signal == SIGINT || signal == SIGTERM) {
        LOG_INFO("Received shutdown signal, stopping server...");
        g_running = false;
    }
}

void printBanner() {
    std::cout << R"(
  ____                    ____  ____ ____    ____                           
 / __ \                  |  _ \/ ___|___ \  / ___|  ___ _ ____   _____ _ __ 
| |  | |_ __   ___ _ __  | | | \___ \ __) | \___ \ / _ \ '__\ \ / / _ \ '__|
| |  | | '_ \ / _ \ '_ \ | |_| |___) / __/   ___) |  __/ |   \ V /  __/ |   
 \____/| .__/ \___/ ._/ |____/|____/_____| |____/ \___|_|    \_/ \___|_|   
       | |       | |                                                        
       |_|       |_|       v0.1.0 - Dead Space 2 Server Emulator            
)" << std::endl;
}

int main(int argc, char* argv[]) {
    printBanner();
    
    // Set up signal handlers
    std::signal(SIGINT, signalHandler);
    std::signal(SIGTERM, signalHandler);
    
    // Load configuration
    std::string configPath = "config/server.ini";
    if (argc > 1) {
        configPath = argv[1];
    }
    
    ds2::Config& config = ds2::Config::getInstance();
    if (!config.load(configPath)) {
        LOG_ERROR("Failed to load configuration from: " + configPath);
        LOG_INFO("Using default configuration values");
    }
    
    // Initialize logger
    ds2::Logger::getInstance().setLevel(
        static_cast<ds2::LogLevel>(config.getInt("log_level", 1))
    );
    
    LOG_INFO("Starting Open DS2 Server...");
    
    // Get Blaze ports from config (or use defaults)
    uint16_t redirectorPort = static_cast<uint16_t>(config.getInt("redirector_port", 42127));
    uint16_t gamePort = static_cast<uint16_t>(config.getInt("blaze_game_port", 10041));
    
    // Get SSL configuration
    bool useSSL = config.getBool("ssl_enabled", true);
    std::string sslCert = config.getString("ssl_cert", "certs/server.crt");
    std::string sslKey = config.getString("ssl_key", "certs/server.key");
    
    LOG_INFO("Redirector port: " + std::to_string(redirectorPort) + 
             (useSSL ? " (SSL)" : " (plain)"));
    LOG_INFO("Game server port: " + std::to_string(gamePort));
    
    // Register Blaze protocol handlers
    ds2::blaze::registerAllHandlers();
    
    // Create and start the Blaze server
    ds2::blaze::BlazeServer server;
    
    // Configure SSL if enabled
    if (useSSL) {
        server.setSSLFiles(sslCert, sslKey);
    }
    
    if (!server.initialize(redirectorPort, gamePort, useSSL)) {
        LOG_ERROR("Failed to initialize Blaze server");
        return 1;
    }
    
    if (!server.start()) {
        LOG_ERROR("Failed to start Blaze server");
        return 1;
    }
    
    LOG_INFO("Server is running. Press Ctrl+C to stop.");
    LOG_INFO("To connect, redirect gosredirector.ea.com to this server's IP");
    
    // Main loop
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    
    // Cleanup
    LOG_INFO("Shutting down server...");
    server.stop();
    
    LOG_INFO("Server stopped successfully");
    return 0;
}
