#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>

#include "blaze_types.hpp"

namespace ds2 {

class Session;

namespace blaze {

/**
 * Blaze packet codec
 * Handles encoding and decoding of Blaze protocol packets
 */
class BlazeCodec {
public:
    /**
     * Decode a Blaze packet from raw data
     * @param data Raw data buffer
     * @param length Buffer length
     * @param packet Output packet
     * @return Number of bytes consumed, or 0 if incomplete
     */
    static size_t decode(const uint8_t* data, size_t length, Packet& packet);
    
    /**
     * Encode a Blaze packet to raw data
     */
    static std::vector<uint8_t> encode(const Packet& packet);
    
    /**
     * Create a reply packet for a request
     */
    static Packet createReply(const Packet& request);
    
    /**
     * Create an error reply
     */
    static Packet createErrorReply(const Packet& request, BlazeError error);
    
    /**
     * Create a notification packet
     */
    static Packet createNotification(ComponentId component, uint16_t command);
};

/**
 * Component handler function type
 */
using ComponentHandler = std::function<void(std::shared_ptr<Session>, Packet&)>;

/**
 * Blaze component router
 * Routes incoming packets to appropriate handlers
 */
class BlazeRouter {
public:
    static BlazeRouter& getInstance() {
        static BlazeRouter instance;
        return instance;
    }
    
    /**
     * Register a handler for a component+command
     */
    void registerHandler(ComponentId component, uint16_t command, ComponentHandler handler);
    
    /**
     * Route a packet to its handler
     */
    void route(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Check if handler exists
     */
    bool hasHandler(ComponentId component, uint16_t command) const;
    
private:
    BlazeRouter() = default;
    
    using HandlerKey = uint32_t;
    static HandlerKey makeKey(ComponentId component, uint16_t command) {
        return (static_cast<uint32_t>(component) << 16) | command;
    }
    
    std::map<HandlerKey, ComponentHandler> m_handlers;
};

/**
 * Macro for registering Blaze handlers
 */
#define BLAZE_HANDLER(component, command, handler) \
    ds2::blaze::BlazeRouter::getInstance().registerHandler( \
        ds2::blaze::ComponentId::component, \
        static_cast<uint16_t>(ds2::blaze::component##Command::command), \
        handler)

} // namespace blaze
} // namespace ds2
