#include "core/log.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <mutex>

namespace opends2::log {

namespace {
std::atomic<Level> g_level{Level::Info};
std::mutex g_mutex;
}  // namespace

void set_level(Level level) { g_level.store(level, std::memory_order_relaxed); }

Level level() { return g_level.load(std::memory_order_relaxed); }

std::optional<Level> parse_level(std::string_view name) {
    if (name == "trace") return Level::Trace;
    if (name == "debug") return Level::Debug;
    if (name == "info") return Level::Info;
    if (name == "warn") return Level::Warn;
    if (name == "error") return Level::Error;
    return std::nullopt;
}

std::string_view to_string(Level level) {
    switch (level) {
        case Level::Trace: return "trace";
        case Level::Debug: return "debug";
        case Level::Info: return "info";
        case Level::Warn: return "warn";
        case Level::Error: return "error";
    }
    return "?";
}

void write(Level level, std::string_view message) {
    const auto now = std::chrono::floor<std::chrono::milliseconds>(std::chrono::system_clock::now());
    const auto line = std::format("[{:%F %T}Z] [{}] {}\n", now, to_string(level), message);

    std::lock_guard lock(g_mutex);
    std::fputs(line.c_str(), stderr);
}

}  // namespace opends2::log
