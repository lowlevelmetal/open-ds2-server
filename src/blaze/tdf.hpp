#pragma once

#include <vector>
#include <string>
#include <cstdint>
#include <memory>

#include "blaze_types.hpp"

namespace ds2 {
namespace blaze {

/**
 * TDF Writer - Encodes data in Blaze TDF format
 */
class TdfWriter {
public:
    TdfWriter();
    
    /**
     * Write a tag with label
     * Label should be 4 characters, uppercase
     */
    void writeTag(const char* label, TdfType type);
    
    /**
     * Write integer (variable-length encoded)
     */
    void writeInteger(const char* label, int64_t value);
    void writeInteger(int64_t value);  // Without tag
    
    /**
     * Write string
     */
    void writeString(const char* label, const std::string& value);
    void writeString(const std::string& value);  // Without tag
    
    /**
     * Write binary blob
     */
    void writeBlob(const char* label, const std::vector<uint8_t>& data);
    void writeBlob(const std::vector<uint8_t>& data);  // Without tag
    
    /**
     * Start a structure
     */
    void startStruct(const char* label);
    void endStruct();
    
    /**
     * Start a list
     */
    void startList(const char* label, TdfType elementType, size_t count);
    void endList();
    
    /**
     * Start a map
     */
    void startMap(const char* label, TdfType keyType, TdfType valueType, size_t count);
    void endMap();
    
    /**
     * Write union
     */
    void writeUnion(const char* label, uint8_t activeField);
    
    /**
     * Write object type
     */
    void writeObjectType(const char* label, uint16_t component, uint16_t type);
    
    /**
     * Write object ID
     */
    void writeObjectId(const char* label, uint16_t component, uint16_t type, uint64_t id);
    
    /**
     * Write float
     */
    void writeFloat(const char* label, float value);
    
    /**
     * Get encoded data
     */
    const std::vector<uint8_t>& getData() const { return m_data; }
    std::vector<uint8_t> take() { return std::move(m_data); }
    
    /**
     * Clear buffer
     */
    void clear() { m_data.clear(); }
    
private:
    void encodeTag(const char* label, TdfType type);
    void encodeVarInt(uint64_t value);
    
    std::vector<uint8_t> m_data;
};

/**
 * TDF Reader - Decodes Blaze TDF format
 */
class TdfReader {
public:
    TdfReader(const uint8_t* data, size_t size);
    TdfReader(const std::vector<uint8_t>& data);
    
    /**
     * Read next tag
     * Returns false if no more data
     */
    bool readTag(std::string& label, TdfType& type);
    
    /**
     * Read integer
     */
    int64_t readInteger();
    
    /**
     * Read unsigned integer
     */
    uint64_t readUInteger();
    
    /**
     * Read string
     */
    std::string readString();
    
    /**
     * Read binary blob
     */
    std::vector<uint8_t> readBlob();
    
    /**
     * Read list header
     * Returns element type and count
     */
    void readListHeader(TdfType& elementType, size_t& count);
    
    /**
     * Read map header
     */
    void readMapHeader(TdfType& keyType, TdfType& valueType, size_t& count);
    
    /**
     * Read struct start marker (0x00)
     */
    void readStructStart();
    
    /**
     * Read struct end marker (0x00)
     */
    void readStructEnd();
    
    /**
     * Read union (returns active field)
     */
    uint8_t readUnion();
    
    /**
     * Read object type
     */
    void readObjectType(uint16_t& component, uint16_t& type);
    
    /**
     * Read object ID
     */
    void readObjectId(uint16_t& component, uint16_t& type, uint64_t& id);
    
    /**
     * Read float
     */
    float readFloat();
    
    /**
     * Skip current value based on type
     */
    void skipValue(TdfType type);
    
    /**
     * Check if more data available
     */
    bool hasMore() const { return m_pos < m_size; }
    
    /**
     * Get current position
     */
    size_t position() const { return m_pos; }
    
    /**
     * Get remaining bytes
     */
    size_t remaining() const { return m_size - m_pos; }
    
private:
    uint64_t decodeVarInt();
    void checkBounds(size_t needed);
    
    const uint8_t* m_data;
    size_t m_size;
    size_t m_pos;
};

/**
 * Encode a 4-character label into Blaze tag format
 * Labels are encoded as base-32 in a 24-bit value
 */
uint32_t encodeLabel(const char* label);

/**
 * Decode a Blaze tag label back to string
 */
std::string decodeLabel(uint32_t encoded);

} // namespace blaze
} // namespace ds2
