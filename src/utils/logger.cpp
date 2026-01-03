#include "logger.hpp"

namespace ds2 {

Logger::~Logger() {
    if (m_file.is_open()) {
        m_file.close();
    }
}

bool Logger::setLogFile(const std::string& path) {
    std::lock_guard<std::mutex> lock(m_mutex);
    
    if (m_file.is_open()) {
        m_file.close();
    }
    
    m_file.open(path, std::ios::out | std::ios::app);
    return m_file.is_open();
}

void Logger::log(LogLevel level, const std::string& message, const char* file, int line) {
    if (level < m_level) {
        return;
    }
    
    std::lock_guard<std::mutex> lock(m_mutex);
    
    std::ostringstream ss;
    ss << "[" << getTimestamp() << "] ";
    ss << "[" << levelToString(level) << "] ";
    
    // Add file and line for debug builds
#ifdef _DEBUG
    if (file) {
        // Extract just the filename
        std::string filepath(file);
        size_t pos = filepath.find_last_of("/\\");
        if (pos != std::string::npos) {
            filepath = filepath.substr(pos + 1);
        }
        ss << "[" << filepath << ":" << line << "] ";
    }
#else
    (void)file;
    (void)line;
#endif
    
    ss << message;
    
    std::string output = ss.str();
    
    // Console output with colors
    if (m_consoleOutput) {
        const char* color = "";
        const char* reset = "\033[0m";
        
        switch (level) {
            case LogLevel::Debug:   color = "\033[36m"; break; // Cyan
            case LogLevel::Info:    color = "\033[32m"; break; // Green
            case LogLevel::Warning: color = "\033[33m"; break; // Yellow
            case LogLevel::Error:   color = "\033[31m"; break; // Red
            default: break;
        }
        
        std::cout << color << output << reset << std::endl;
    }
    
    // File output
    if (m_file.is_open()) {
        m_file << output << std::endl;
        m_file.flush();
    }
}

std::string Logger::levelToString(LogLevel level) const {
    switch (level) {
        case LogLevel::Debug:   return "DEBUG";
        case LogLevel::Info:    return "INFO ";
        case LogLevel::Warning: return "WARN ";
        case LogLevel::Error:   return "ERROR";
        default:                return "?????";
    }
}

std::string Logger::getTimestamp() const {
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    
    std::ostringstream ss;
    ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
    ss << "." << std::setfill('0') << std::setw(3) << ms.count();
    
    return ss.str();
}

} // namespace ds2
