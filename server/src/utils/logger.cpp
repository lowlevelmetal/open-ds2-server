#include "utils/logger.hpp"

namespace ds2::utils {

std::shared_ptr<spdlog::logger> Logger::s_logger;

void Logger::init(const std::string& logFile) {
    try {
        // Create console sink with colors
        auto console_sink = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
        console_sink->set_level(spdlog::level::debug);
        console_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] %v");
        
        // Create file sink with rotation
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            logFile, 1024 * 1024 * 5, 3); // 5MB, 3 files
        file_sink->set_level(spdlog::level::trace);
        file_sink->set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%l] [%t] %v");
        
        // Create logger with both sinks
        s_logger = std::make_shared<spdlog::logger>("ds2", 
            spdlog::sinks_init_list{console_sink, file_sink});
        
        s_logger->set_level(spdlog::level::debug);
        s_logger->flush_on(spdlog::level::warn);
        
        spdlog::register_logger(s_logger);
        spdlog::set_default_logger(s_logger);
        
        s_logger->info("Logger initialized");
    }
    catch (const spdlog::spdlog_ex& ex) {
        fprintf(stderr, "Logger init failed: %s\n", ex.what());
    }
}

void Logger::shutdown() {
    if (s_logger) {
        s_logger->info("Logger shutting down");
        s_logger->flush();
    }
    spdlog::shutdown();
}

} // namespace ds2::utils
