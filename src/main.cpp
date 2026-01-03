/**
 * Open Dead Space 2 Server
 * 
 * An open source implementation of the Dead Space 2 multiplayer server.
 * This project aims to restore online functionality for Dead Space 2.
 */

#include <iostream>
#include <csignal>
#include <atomic>

#include "core/server.hpp"
#include "core/config.hpp"
#include "utils/logger.hpp"
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
    LOG_INFO("Bind address: " + config.getString("bind_address", "0.0.0.0"));
    LOG_INFO("Game port: " + std::to_string(config.getInt("game_port", 28910)));
    
    // Register Blaze protocol handlers
    ds2::blaze::registerAllHandlers();
    
    // Create and start the server
    ds2::Server server;
    
    if (!server.initialize()) {
        LOG_ERROR("Failed to initialize server");
        return 1;
    }
    
    if (!server.start()) {
        LOG_ERROR("Failed to start server");
        return 1;
    }
    
    LOG_INFO("Server is running. Press Ctrl+C to stop.");
    
    // Main loop
    while (g_running) {
        server.update();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Cleanup
    LOG_INFO("Shutting down server...");
    server.stop();
    
    LOG_INFO("Server stopped successfully");
    return 0;
}
