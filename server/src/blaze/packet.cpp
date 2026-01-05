#include "blaze/packet.hpp"
#include "blaze/tdf.hpp"
#include "utils/logger.hpp"
#include <cstring>
#include <arpa/inet.h>

namespace ds2::blaze {

Packet::Packet() {
    std::memset(&m_header, 0, sizeof(m_header));
}

Packet::Packet(ComponentId component, uint16_t command, MessageType msgType, uint16_t msgId) {
    std::memset(&m_header, 0, sizeof(m_header));
    m_header.component = htons(static_cast<uint16_t>(component));
    m_header.command = htons(command);
    m_header.msgType = htons(static_cast<uint16_t>(msgType));
    m_header.msgId = htons(msgId);
}

std::unique_ptr<Packet> Packet::parse(const std::vector<uint8_t>& data) {
    if (data.size() < sizeof(PacketHeader)) {
        LOG_ERROR("Packet too small: {} bytes", data.size());
        return nullptr;
    }
    
    auto packet = std::make_unique<Packet>();
    std::memcpy(&packet->m_header, data.data(), sizeof(PacketHeader));
    
    // Header is big-endian
    uint16_t payloadLen = ntohs(packet->m_header.length);
    
    if (data.size() < sizeof(PacketHeader) + payloadLen) {
        LOG_ERROR("Packet payload incomplete: have {}, need {}", 
                  data.size() - sizeof(PacketHeader), payloadLen);
        return nullptr;
    }
    
    if (payloadLen > 0) {
        packet->m_payload.assign(
            data.begin() + sizeof(PacketHeader),
            data.begin() + sizeof(PacketHeader) + payloadLen
        );
    }
    
    return packet;
}

std::vector<uint8_t> Packet::serialize() const {
    std::vector<uint8_t> data;
    data.reserve(sizeof(PacketHeader) + m_payload.size());
    
    // Create header copy with correct length
    PacketHeader header = m_header;
    header.length = htons(static_cast<uint16_t>(m_payload.size()));
    
    // Append header
    const uint8_t* headerBytes = reinterpret_cast<const uint8_t*>(&header);
    data.insert(data.end(), headerBytes, headerBytes + sizeof(PacketHeader));
    
    // Append payload
    data.insert(data.end(), m_payload.begin(), m_payload.end());
    
    return data;
}

void Packet::setPayload(const TdfStruct& data) {
    TdfEncoder encoder;
    m_payload = encoder.encode(data);
}

TdfStruct Packet::getPayloadAsTdf() const {
    if (m_payload.empty()) {
        return TdfStruct{};
    }
    
    TdfDecoder decoder(m_payload);
    return decoder.decode();
}

void Packet::setComponent(ComponentId component) {
    m_header.component = htons(static_cast<uint16_t>(component));
}

void Packet::setCommand(uint16_t command) {
    m_header.command = htons(command);
}

void Packet::setMessageType(MessageType type) {
    m_header.msgType = htons(static_cast<uint16_t>(type));
}

void Packet::setMessageId(uint16_t id) {
    m_header.msgId = htons(id);
}

void Packet::setError(BlazeError error) {
    m_header.error = htons(static_cast<uint16_t>(error));
}

ComponentId Packet::getComponent() const {
    return static_cast<ComponentId>(ntohs(m_header.component));
}

uint16_t Packet::getCommand() const {
    return ntohs(m_header.command);
}

MessageType Packet::getMessageType() const {
    return static_cast<MessageType>(ntohs(m_header.msgType));
}

uint16_t Packet::getMessageId() const {
    return ntohs(m_header.msgId);
}

BlazeError Packet::getError() const {
    return static_cast<BlazeError>(ntohs(m_header.error));
}

std::unique_ptr<Packet> Packet::createReply() const {
    auto reply = std::make_unique<Packet>();
    reply->m_header = m_header;
    reply->m_header.msgType = htons(static_cast<uint16_t>(MessageType::Reply));
    reply->m_header.error = 0;
    reply->m_header.length = 0;
    return reply;
}

std::unique_ptr<Packet> Packet::createErrorReply(BlazeError error) const {
    auto reply = std::make_unique<Packet>();
    reply->m_header = m_header;
    reply->m_header.msgType = htons(static_cast<uint16_t>(MessageType::ErrorReply));
    reply->m_header.error = htons(static_cast<uint16_t>(error));
    reply->m_header.length = 0;
    return reply;
}

} // namespace ds2::blaze
