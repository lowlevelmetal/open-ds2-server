#pragma once

#include "blaze/types.hpp"
#include <vector>
#include <cstdint>
#include <memory>
#include <string>

namespace ds2::blaze {

/**
 * TDF (Tag Data Format) Encoder/Decoder
 * 
 * TDF is EA's binary serialization format used in the Blaze protocol.
 * Each field has a 3-byte compressed tag and a type byte, followed by the value.
 * 
 * Tag compression: 4 ASCII chars -> 3 bytes (6 bits per char, values 0-38)
 *   A-Z = 1-26, 0-9 = 27-36, _ = 37, space = 0
 */
class TdfEncoder {
public:
    TdfEncoder();
    
    // Encode a full TDF structure
    std::vector<uint8_t> encode(const TdfStruct& data);
    
    // Individual type encoders
    void encodeInteger(const std::string& tag, int64_t value);
    void encodeString(const std::string& tag, const std::string& value);
    void encodeBinary(const std::string& tag, const std::vector<uint8_t>& value);
    void encodeStruct(const std::string& tag, const TdfStruct& value);
    void encodeList(const std::string& tag, TdfType elementType, const TdfList& value);
    void encodeMap(const std::string& tag, TdfType keyType, TdfType valueType, const TdfMapWrapper& value);
    void encodeIntList(const std::string& tag, const TdfIntList& value);
    void encodePair(const std::string& tag, const TdfPair& value);
    void encodeTriple(const std::string& tag, const TdfTriple& value);
    void encodeFloat(const std::string& tag, float value);
    
    // Get encoded data
    std::vector<uint8_t> getData() const { return m_buffer; }
    
    // Reset encoder
    void reset() { m_buffer.clear(); }
    
private:
    std::vector<uint8_t> m_buffer;
    
    // Encode tag (4 chars -> 3 bytes)
    void encodeTag(const std::string& tag);
    
    // Encode variable-length integer
    void encodeVarInt(int64_t value);
    
    // Encode unsigned variable-length integer
    void encodeVarUInt(uint64_t value);
    
    // Write raw bytes
    void writeBytes(const void* data, size_t size);
    void writeByte(uint8_t byte);
};

/**
 * TDF Decoder
 */
class TdfDecoder {
public:
    TdfDecoder(const std::vector<uint8_t>& data);
    TdfDecoder(const uint8_t* data, size_t size);
    
    // Decode entire structure
    TdfStruct decode();
    
    // Check if more data available
    bool hasMore() const { return m_pos < m_size; }
    
    // Get current position
    size_t getPosition() const { return m_pos; }
    
private:
    const uint8_t* m_data;
    size_t m_size;
    size_t m_pos;
    
    // Decode tag (3 bytes -> 4 chars)
    std::string decodeTag();
    
    // Decode type byte
    TdfType decodeType();
    
    // Decode variable-length integer
    int64_t decodeVarInt();
    uint64_t decodeVarUInt();
    
    // Decode specific types
    TdfInteger decodeInteger();
    TdfString decodeString();
    TdfBinary decodeBinary();
    TdfStruct decodeStruct();
    TdfList decodeList();
    TdfMapWrapper decodeMap();
    TdfIntList decodeIntList();
    TdfPair decodePair();
    TdfTriple decodeTriple();
    float decodeFloat();
    
    // Read helpers
    uint8_t readByte();
    void readBytes(void* dest, size_t size);
};

/**
 * Helper to build TDF structures fluently
 */
class TdfBuilder {
public:
    TdfBuilder() = default;
    
    TdfBuilder& integer(const std::string& tag, int64_t value);
    TdfBuilder& string(const std::string& tag, const std::string& value);
    TdfBuilder& binary(const std::string& tag, const std::vector<uint8_t>& value);
    TdfBuilder& pair(const std::string& tag, int64_t first, int64_t second);
    TdfBuilder& triple(const std::string& tag, uint32_t ip, uint16_t port, uint16_t protocol = 2);
    TdfBuilder& intList(const std::string& tag, const std::vector<int64_t>& values);
    
    // Nested struct
    TdfBuilder& beginStruct(const std::string& tag);
    TdfBuilder& endStruct();
    
    // Build final structure
    TdfStruct build();
    
    // Encode to bytes
    std::vector<uint8_t> encode();
    
private:
    TdfStruct m_root;
    std::vector<TdfStruct*> m_stack;
    std::vector<std::string> m_tagStack;
    
    TdfStruct& current();
};

} // namespace ds2::blaze
