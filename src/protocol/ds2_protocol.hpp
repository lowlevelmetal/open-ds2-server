#pragma once

#include <cstdint>
#include <vector>
#include <string>

#include "network/packet.hpp"

namespace ds2 {
namespace protocol {

/**
 * Dead Space 2 Protocol Handler
 * 
 * This class handles parsing and building packets according to the DS2 protocol.
 * The actual packet format will need to be discovered through reverse engineering.
 */
class DS2Protocol {
public:
    /**
     * Parse a packet from raw data
     * @param data Raw data buffer
     * @param length Buffer length
     * @param packet Output packet
     * @return Number of bytes consumed, or 0 if incomplete packet
     */
    static size_t parsePacket(const uint8_t* data, size_t length, network::Packet& packet);
    
    /**
     * Build raw data from a packet
     */
    static std::vector<uint8_t> buildPacket(const network::Packet& packet);
    
    /**
     * Validate packet checksum
     */
    static bool validateChecksum(const uint8_t* data, size_t length);
    
    /**
     * Calculate packet checksum
     */
    static uint32_t calculateChecksum(const uint8_t* data, size_t length);
    
    /**
     * Get protocol version string
     */
    static std::string getVersionString();
    
    // Protocol constants
    static constexpr uint16_t MAGIC = 0x4453;  // "DS" in little-endian (placeholder)
    static constexpr uint8_t VERSION = 1;
    static constexpr size_t MIN_PACKET_SIZE = 8;  // Minimum header size
    static constexpr size_t MAX_PACKET_SIZE = 65536;
};

} // namespace protocol
} // namespace ds2
