#pragma once

#include <string>
#include <mutex>
#include <fstream>
#include <sstream>
#include <iostream>
#include <chrono>
#include <iomanip>

namespace ds2 {

enum class LogLevel {
    Debug = 0,
    Info = 1,
    Warning = 2,
    Error = 3,
    None = 4
};

/**
 * Thread-safe logger
 */
class Logger {
public:
    static Logger& getInstance() {
        static Logger instance;
        return instance;
    }
    
    // Disable copy
    Logger(const Logger&) = delete;
    Logger& operator=(const Logger&) = delete;
    
    /**
     * Set minimum log level
     */
    void setLevel(LogLevel level) { m_level = level; }
    
    /**
     * Get current log level
     */
    LogLevel getLevel() const { return m_level; }
    
    /**
     * Set log output file
     */
    bool setLogFile(const std::string& path);
    
    /**
     * Enable/disable console output
     */
    void setConsoleOutput(bool enabled) { m_consoleOutput = enabled; }
    
    /**
     * Log a message
     */
    void log(LogLevel level, const std::string& message, 
             const char* file = nullptr, int line = 0);
    
private:
    Logger() = default;
    ~Logger();
    
    std::string levelToString(LogLevel level) const;
    std::string getTimestamp() const;
    
    LogLevel m_level{LogLevel::Info};
    bool m_consoleOutput{true};
    std::ofstream m_file;
    std::mutex m_mutex;
};

// Convenience macros
#define LOG_DEBUG(msg) \
    ds2::Logger::getInstance().log(ds2::LogLevel::Debug, msg, __FILE__, __LINE__)

#define LOG_INFO(msg) \
    ds2::Logger::getInstance().log(ds2::LogLevel::Info, msg, __FILE__, __LINE__)

#define LOG_WARN(msg) \
    ds2::Logger::getInstance().log(ds2::LogLevel::Warning, msg, __FILE__, __LINE__)

#define LOG_ERROR(msg) \
    ds2::Logger::getInstance().log(ds2::LogLevel::Error, msg, __FILE__, __LINE__)

} // namespace ds2
