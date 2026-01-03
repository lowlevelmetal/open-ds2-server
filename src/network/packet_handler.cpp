#include "packet_handler.hpp"
#include "utils/logger.hpp"

namespace ds2 {
namespace network {

void PacketHandler::registerHandler(PacketType type, PacketHandlerFunc handler) {
    m_handlers[type] = std::move(handler);
    LOG_DEBUG("Registered handler for packet type: " + std::to_string(static_cast<int>(type)));
}

void PacketHandler::unregisterHandler(PacketType type) {
    m_handlers.erase(type);
}

void PacketHandler::dispatch(std::shared_ptr<Session> session, const Packet& packet) {
    auto it = m_handlers.find(packet.type);
    if (it != m_handlers.end()) {
        it->second(session, packet);
    } else {
        LOG_WARN("No handler for packet type: " + std::to_string(static_cast<int>(packet.type)));
    }
}

bool PacketHandler::hasHandler(PacketType type) const {
    return m_handlers.find(type) != m_handlers.end();
}

} // namespace network
} // namespace ds2
