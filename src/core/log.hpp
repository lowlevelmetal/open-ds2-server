#pragma once

#include <format>
#include <optional>
#include <string_view>
#include <utility>

namespace opends2::log {

enum class Level { Trace, Debug, Info, Warn, Error };

void set_level(Level level);
Level level();
std::optional<Level> parse_level(std::string_view name);
std::string_view to_string(Level level);

void write(Level level, std::string_view message);

inline bool enabled(Level l) { return l >= level(); }

template <class... Args>
void trace(std::format_string<Args...> fmt, Args&&... args) {
    if (enabled(Level::Trace)) write(Level::Trace, std::format(fmt, std::forward<Args>(args)...));
}

template <class... Args>
void debug(std::format_string<Args...> fmt, Args&&... args) {
    if (enabled(Level::Debug)) write(Level::Debug, std::format(fmt, std::forward<Args>(args)...));
}

template <class... Args>
void info(std::format_string<Args...> fmt, Args&&... args) {
    if (enabled(Level::Info)) write(Level::Info, std::format(fmt, std::forward<Args>(args)...));
}

template <class... Args>
void warn(std::format_string<Args...> fmt, Args&&... args) {
    if (enabled(Level::Warn)) write(Level::Warn, std::format(fmt, std::forward<Args>(args)...));
}

template <class... Args>
void error(std::format_string<Args...> fmt, Args&&... args) {
    if (enabled(Level::Error)) write(Level::Error, std::format(fmt, std::forward<Args>(args)...));
}

}  // namespace opends2::log
