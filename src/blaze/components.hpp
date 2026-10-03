#pragma once

// Blaze component and command IDs.
//
// These values come from ME3/BF3-era Blaze 3 research. Treat every entry as a
// hypothesis until it has been confirmed against Dead Space 2. When you confirm
// one, note it in docs/PROTOCOL.md.

#include <cstdint>
#include <string_view>

namespace opends2::blaze {

namespace component {
inline constexpr std::uint16_t Authentication = 0x0001;
inline constexpr std::uint16_t GameManager = 0x0004;
inline constexpr std::uint16_t Redirector = 0x0005;
inline constexpr std::uint16_t Stats = 0x0007;
inline constexpr std::uint16_t Util = 0x0009;
inline constexpr std::uint16_t Messaging = 0x000F;
inline constexpr std::uint16_t AssociationLists = 0x0019;
inline constexpr std::uint16_t GameReporting = 0x001C;
inline constexpr std::uint16_t UserSessions = 0x7802;
}  // namespace component

namespace redirector {
inline constexpr std::uint16_t GetServerInstance = 0x0001;
}  // namespace redirector

namespace util {
inline constexpr std::uint16_t FetchClientConfig = 0x0001;
inline constexpr std::uint16_t Ping = 0x0002;
inline constexpr std::uint16_t PreAuth = 0x0007;
inline constexpr std::uint16_t PostAuth = 0x0008;
}  // namespace util

constexpr std::string_view component_name(std::uint16_t id) {
    switch (id) {
        case component::Authentication: return "Authentication";
        case component::GameManager: return "GameManager";
        case component::Redirector: return "Redirector";
        case component::Stats: return "Stats";
        case component::Util: return "Util";
        case component::Messaging: return "Messaging";
        case component::AssociationLists: return "AssociationLists";
        case component::GameReporting: return "GameReporting";
        case component::UserSessions: return "UserSessions";
        default: return "Unknown";
    }
}

}  // namespace opends2::blaze
