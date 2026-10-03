#include <csignal>
#include <cstdio>
#include <exception>
#include <filesystem>
#include <optional>
#include <string_view>

#include <asio/io_context.hpp>
#include <asio/signal_set.hpp>

#include "core/config.hpp"
#include "core/log.hpp"
#include "server/server.hpp"
#include "services/services.hpp"

namespace {

constexpr std::string_view kUsage =
    "usage: opends2server [--config <path>] [--log-level <trace|debug|info|warn|error>]\n";

}  // namespace

int main(int argc, char** argv) {
    using namespace opends2;

    std::optional<std::filesystem::path> config_path;
    std::optional<log::Level> level_override;

    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if ((arg == "--config" || arg == "-c") && i + 1 < argc) {
            config_path = argv[++i];
        } else if (arg == "--log-level" && i + 1 < argc) {
            level_override = log::parse_level(argv[++i]);
            if (!level_override) {
                std::fputs(kUsage.data(), stderr);
                return 2;
            }
        } else if (arg == "--help" || arg == "-h") {
            std::fputs(kUsage.data(), stdout);
            return 0;
        } else {
            std::fputs(kUsage.data(), stderr);
            return 2;
        }
    }

    try {
        const Config config = config_path ? load_config(*config_path) : Config{};
        log::set_level(level_override.value_or(config.log_level));

        asio::io_context io(1);

        Server server(io, config);
        services::register_all(server.router(), config);
        server.start();

        asio::signal_set signals(io, SIGINT, SIGTERM);
        signals.async_wait([&io](const asio::error_code&, int) {
            log::info("shutting down");
            io.stop();
        });

        io.run();
    } catch (const std::exception& e) {
        log::error("fatal: {}", e.what());
        return 1;
    }
    return 0;
}
