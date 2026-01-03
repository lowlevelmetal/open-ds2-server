#include "blaze_codec.hpp"
#include "utils/logger.hpp"

#include <cstring>

namespace ds2 {
namespace blaze {

size_t BlazeCodec::decode(const uint8_t* data, size_t length, Packet& packet) {
    // Minimum packet size is header only
    if (length < HEADER_SIZE) {
        return 0;  // Need more data
    }
    
    // Read header (big-endian)
    uint16_t packetLen = (data[0] << 8) | data[1];
    
    // Total packet size includes the length field itself
    size_t totalSize = packetLen + 2;
    
    if (length < totalSize) {
        return 0;  // Need more data
    }
    
    // Parse header fields
    packet.component = static_cast<ComponentId>((data[2] << 8) | data[3]);
    packet.command = (data[4] << 8) | data[5];
    packet.errorCode = (data[6] << 8) | data[7];
    packet.type = static_cast<PacketType>((data[8] << 8) | data[9]);
    packet.msgId = (data[10] << 8) | data[11];
    
    // Copy payload
    size_t payloadSize = totalSize - HEADER_SIZE;
    if (payloadSize > 0) {
        packet.payload.assign(data + HEADER_SIZE, data + totalSize);
    } else {
        packet.payload.clear();
    }
    
    LOG_DEBUG("Decoded Blaze packet: component=0x" + 
              std::to_string(static_cast<uint16_t>(packet.component)) +
              " command=0x" + std::to_string(packet.command) +
              " type=0x" + std::to_string(static_cast<uint16_t>(packet.type)) +
              " msgId=" + std::to_string(packet.msgId) +
              " payload=" + std::to_string(payloadSize) + " bytes");
    
    return totalSize;
}

std::vector<uint8_t> BlazeCodec::encode(const Packet& packet) {
    size_t payloadLen = packet.payload.size();
    size_t totalLen = HEADER_SIZE + payloadLen;
    
    std::vector<uint8_t> data(totalLen);
    
    // Length field (excludes itself)
    uint16_t len = static_cast<uint16_t>(totalLen - 2);
    data[0] = (len >> 8) & 0xFF;
    data[1] = len & 0xFF;
    
    // Component
    uint16_t comp = static_cast<uint16_t>(packet.component);
    data[2] = (comp >> 8) & 0xFF;
    data[3] = comp & 0xFF;
    
    // Command
    data[4] = (packet.command >> 8) & 0xFF;
    data[5] = packet.command & 0xFF;
    
    // Error code
    data[6] = (packet.errorCode >> 8) & 0xFF;
    data[7] = packet.errorCode & 0xFF;
    
    // Message type
    uint16_t msgType = static_cast<uint16_t>(packet.type);
    data[8] = (msgType >> 8) & 0xFF;
    data[9] = msgType & 0xFF;
    
    // Message ID
    data[10] = (packet.msgId >> 8) & 0xFF;
    data[11] = packet.msgId & 0xFF;
    
    // Payload
    if (payloadLen > 0) {
        std::memcpy(data.data() + HEADER_SIZE, packet.payload.data(), payloadLen);
    }
    
    return data;
}

Packet BlazeCodec::createReply(const Packet& request) {
    Packet reply;
    reply.component = request.component;
    reply.command = request.command;
    reply.type = PacketType::Reply;
    reply.msgId = request.msgId;
    reply.errorCode = 0;
    return reply;
}

Packet BlazeCodec::createErrorReply(const Packet& request, BlazeError error) {
    Packet reply;
    reply.component = request.component;
    reply.command = request.command;
    reply.type = PacketType::ErrorReply;
    reply.msgId = request.msgId;
    reply.errorCode = static_cast<uint16_t>(error);
    return reply;
}

Packet BlazeCodec::createNotification(ComponentId component, uint16_t command) {
    static uint16_t notifyId = 0;
    
    Packet notify;
    notify.component = component;
    notify.command = command;
    notify.type = PacketType::Notification;
    notify.msgId = ++notifyId;
    notify.errorCode = 0;
    return notify;
}

// =============================================================================
// BlazeRouter
// =============================================================================

void BlazeRouter::registerHandler(ComponentId component, uint16_t command, ComponentHandler handler) {
    HandlerKey key = makeKey(component, command);
    m_handlers[key] = std::move(handler);
    
    LOG_DEBUG("Registered Blaze handler: component=0x" + 
              std::to_string(static_cast<uint16_t>(component)) +
              " command=0x" + std::to_string(command));
}

void BlazeRouter::route(std::shared_ptr<Session> session, Packet& packet) {
    HandlerKey key = makeKey(packet.component, packet.command);
    
    auto it = m_handlers.find(key);
    if (it != m_handlers.end()) {
        it->second(session, packet);
    } else {
        LOG_WARN("No handler for Blaze packet: component=0x" + 
                 std::to_string(static_cast<uint16_t>(packet.component)) +
                 " command=0x" + std::to_string(packet.command));
        
        // Send error response
        // TODO: Implement session sending
    }
}

bool BlazeRouter::hasHandler(ComponentId component, uint16_t command) const {
    return m_handlers.find(makeKey(component, command)) != m_handlers.end();
}

} // namespace blaze
} // namespace ds2
