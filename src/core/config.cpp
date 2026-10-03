#include "core/config.hpp"

#include <charconv>
#include <format>
#include <fstream>
#include <sstream>
#include <stdexcept>

namespace opends2 {

namespace {

std::string_view trim(std::string_view s) {
    constexpr std::string_view kSpace = " \t\r\n";
    const auto first = s.find_first_not_of(kSpace);
    if (first == std::string_view::npos) return {};
    const auto last = s.find_last_not_of(kSpace);
    return s.substr(first, last - first + 1);
}

std::uint16_t parse_port(std::string_view value) {
    unsigned port = 0;
    const auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), port);
    if (ec != std::errc{} || end != value.data() + value.size() || port == 0 || port > 65535) {
        throw std::invalid_argument(std::format("invalid port '{}'", value));
    }
    return static_cast<std::uint16_t>(port);
}

void apply(Config& config, std::string_view key, std::string_view value) {
    if (key == "bind_address") {
        config.bind_address = value;
    } else if (key == "redirector_port") {
        config.redirector_port = parse_port(value);
    } else if (key == "blaze_port") {
        config.blaze_port = parse_port(value);
    } else if (key == "public_host") {
        config.public_host = value;
    } else if (key == "log_level") {
        const auto level = log::parse_level(value);
        if (!level) throw std::invalid_argument(std::format("invalid log level '{}'", value));
        config.log_level = *level;
    } else {
        throw std::invalid_argument(std::format("unknown key '{}'", key));
    }
}

}  // namespace

Config parse_config(std::string_view text) {
    Config config;
    std::size_t line_no = 0;

    while (!text.empty()) {
        ++line_no;
        const auto eol = text.find('\n');
        std::string_view line = text.substr(0, eol);
        text = eol == std::string_view::npos ? std::string_view{} : text.substr(eol + 1);

        if (const auto comment = line.find_first_of("#;"); comment != std::string_view::npos) {
            line = line.substr(0, comment);
        }
        line = trim(line);
        if (line.empty()) continue;

        const auto eq = line.find('=');
        if (eq == std::string_view::npos) {
            throw std::runtime_error(std::format("config line {}: expected 'key = value'", line_no));
        }
        try {
            apply(config, trim(line.substr(0, eq)), trim(line.substr(eq + 1)));
        } catch (const std::invalid_argument& e) {
            throw std::runtime_error(std::format("config line {}: {}", line_no, e.what()));
        }
    }
    return config;
}

Config load_config(const std::filesystem::path& path) {
    std::ifstream file(path);
    if (!file) {
        throw std::runtime_error(std::format("cannot open config file '{}'", path.string()));
    }
    std::ostringstream contents;
    contents << file.rdbuf();
    return parse_config(contents.str());
}

}  // namespace opends2
