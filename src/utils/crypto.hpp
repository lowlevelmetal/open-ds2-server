#pragma once

#include <cstdint>
#include <vector>
#include <string>

namespace ds2 {

/**
 * Basic cryptographic utilities
 * Used for packet checksums, authentication, etc.
 */
class Crypto {
public:
    /**
     * Calculate CRC32 checksum
     */
    static uint32_t crc32(const uint8_t* data, size_t length);
    static uint32_t crc32(const std::vector<uint8_t>& data);
    
    /**
     * Calculate MD5 hash
     */
    static std::vector<uint8_t> md5(const uint8_t* data, size_t length);
    static std::vector<uint8_t> md5(const std::string& str);
    
    /**
     * XOR encryption/decryption
     */
    static void xorEncrypt(uint8_t* data, size_t length, const uint8_t* key, size_t keyLength);
    static void xorEncrypt(std::vector<uint8_t>& data, const std::vector<uint8_t>& key);
    
    /**
     * Convert bytes to hex string
     */
    static std::string toHex(const uint8_t* data, size_t length);
    static std::string toHex(const std::vector<uint8_t>& data);
    
    /**
     * Convert hex string to bytes
     */
    static std::vector<uint8_t> fromHex(const std::string& hex);
    
    /**
     * Generate random bytes
     */
    static std::vector<uint8_t> randomBytes(size_t count);
    
private:
    static const uint32_t s_crc32Table[256];
};

} // namespace ds2
