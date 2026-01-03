#pragma once

#include <functional>
#include <map>
#include <memory>

#include "packet.hpp"

namespace ds2 {

class Session;

namespace network {

using PacketHandlerFunc = std::function<void(std::shared_ptr<Session>, const Packet&)>;

/**
 * Packet handler registry and dispatcher
 */
class PacketHandler {
public:
    static PacketHandler& getInstance() {
        static PacketHandler instance;
        return instance;
    }
    
    // Disable copy
    PacketHandler(const PacketHandler&) = delete;
    PacketHandler& operator=(const PacketHandler&) = delete;
    
    /**
     * Register a handler for a packet type
     */
    void registerHandler(PacketType type, PacketHandlerFunc handler);
    
    /**
     * Unregister a handler
     */
    void unregisterHandler(PacketType type);
    
    /**
     * Dispatch a packet to its handler
     */
    void dispatch(std::shared_ptr<Session> session, const Packet& packet);
    
    /**
     * Check if a handler exists for a packet type
     */
    bool hasHandler(PacketType type) const;
    
private:
    PacketHandler() = default;
    ~PacketHandler() = default;
    
    std::map<PacketType, PacketHandlerFunc> m_handlers;
};

/**
 * Helper macro for registering packet handlers
 */
#define REGISTER_PACKET_HANDLER(type, handler) \
    ds2::network::PacketHandler::getInstance().registerHandler( \
        ds2::network::PacketType::type, handler)

} // namespace network
} // namespace ds2
