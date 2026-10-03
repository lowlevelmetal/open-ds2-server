#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <string_view>

#include "core/log.hpp"

namespace opends2 {

struct Config {
    std::string bind_address = "0.0.0.0";

    // Port the game's redirector lookup lands on (after DNS/hosts redirection).
    std::uint16_t redirector_port = 42127;

    // Port of the main Blaze server that the redirector points clients at.
    std::uint16_t blaze_port = 10041;

    // Host/IP the redirector hands to clients. Must be reachable from the game.
    std::string public_host = "127.0.0.1";

    log::Level log_level = log::Level::Info;
};

// Parses "key = value" lines; '#' and ';' start comments. Throws std::runtime_error
// on unknown keys or bad values so typos don't go unnoticed.
Config parse_config(std::string_view text);
Config load_config(const std::filesystem::path& path);

}  // namespace opends2
