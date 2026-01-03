#include "ds2_protocol.hpp"
#include "utils/buffer.hpp"
#include "utils/crypto.hpp"
#include "utils/logger.hpp"

namespace ds2 {
namespace protocol {

/**
 * Packet Format (placeholder - needs reverse engineering):
 * 
 * Offset | Size | Description
 * -------|------|------------
 *    0   |   2  | Magic (0x4453 "DS")
 *    2   |   2  | Packet Type
 *    4   |   4  | Data Length
 *    8   |   4  | Sequence Number
 *   12   |   4  | Checksum (CRC32 of data)
 *   16   |   N  | Data
 */

size_t DS2Protocol::parsePacket(const uint8_t* data, size_t length, network::Packet& packet) {
    // Check minimum size for header
    if (length < MIN_PACKET_SIZE) {
        return 0;  // Need more data
    }
    
    BufferReader reader(data, length);
    
    // Read and verify magic
    uint16_t magic = reader.readU16();
    if (magic != MAGIC) {
        LOG_WARN("Invalid packet magic: 0x" + std::to_string(magic));
        // For now, try to recover by treating it as raw data
        // In production, you might want to disconnect or resync
    }
    
    // Read packet type
    uint16_t packetType = reader.readU16();
    
    // Read data length
    uint32_t dataLength = reader.readU32();
    
    // Validate length
    if (dataLength > MAX_PACKET_SIZE - MIN_PACKET_SIZE) {
        LOG_ERROR("Packet too large: " + std::to_string(dataLength));
        return 0;
    }
    
    // Check if we have enough data
    size_t totalSize = MIN_PACKET_SIZE + dataLength;
    if (length < totalSize) {
        return 0;  // Need more data
    }
    
    // Read sequence and checksum (if present)
    // This depends on actual protocol format
    
    // Read data
    packet.type = static_cast<network::PacketType>(packetType);
    packet.data = reader.readBytes(dataLength);
    
    // TODO: Validate checksum
    
    return totalSize;
}

std::vector<uint8_t> DS2Protocol::buildPacket(const network::Packet& packet) {
    BufferWriter writer(MIN_PACKET_SIZE + packet.data.size());
    
    // Write header
    writer.writeU16(MAGIC);
    writer.writeU16(static_cast<uint16_t>(packet.type));
    writer.writeU32(static_cast<uint32_t>(packet.data.size()));
    
    // Write data
    writer.writeBytes(packet.data);
    
    // TODO: Calculate and append checksum
    
    return std::move(writer.take());
}

bool DS2Protocol::validateChecksum(const uint8_t* data, size_t length) {
    if (length < MIN_PACKET_SIZE) {
        return false;
    }
    
    // TODO: Extract checksum from packet and verify
    // This depends on actual packet format
    
    return true;
}

uint32_t DS2Protocol::calculateChecksum(const uint8_t* data, size_t length) {
    return Crypto::crc32(data, length);
}

std::string DS2Protocol::getVersionString() {
    return "DS2Protocol v" + std::to_string(VERSION);
}

} // namespace protocol
} // namespace ds2
