#pragma once

#include <cstdint>
#include <vector>
#include <string>
#include <cstring>
#include <stdexcept>

namespace ds2 {

/**
 * Buffer reader for parsing binary data
 */
class BufferReader {
public:
    explicit BufferReader(const std::vector<uint8_t>& data)
        : m_data(data.data())
        , m_size(data.size())
        , m_pos(0)
    {}
    
    BufferReader(const uint8_t* data, size_t size)
        : m_data(data)
        , m_size(size)
        , m_pos(0)
    {}
    
    // Read primitives (little-endian)
    uint8_t readU8() {
        checkBounds(1);
        return m_data[m_pos++];
    }
    
    int8_t readI8() {
        return static_cast<int8_t>(readU8());
    }
    
    uint16_t readU16() {
        checkBounds(2);
        uint16_t value = m_data[m_pos] | (m_data[m_pos + 1] << 8);
        m_pos += 2;
        return value;
    }
    
    int16_t readI16() {
        return static_cast<int16_t>(readU16());
    }
    
    uint32_t readU32() {
        checkBounds(4);
        uint32_t value = m_data[m_pos] | 
                        (m_data[m_pos + 1] << 8) |
                        (m_data[m_pos + 2] << 16) |
                        (m_data[m_pos + 3] << 24);
        m_pos += 4;
        return value;
    }
    
    int32_t readI32() {
        return static_cast<int32_t>(readU32());
    }
    
    uint64_t readU64() {
        checkBounds(8);
        uint64_t value = 0;
        for (int i = 0; i < 8; i++) {
            value |= static_cast<uint64_t>(m_data[m_pos + i]) << (i * 8);
        }
        m_pos += 8;
        return value;
    }
    
    int64_t readI64() {
        return static_cast<int64_t>(readU64());
    }
    
    float readFloat() {
        uint32_t bits = readU32();
        float value;
        std::memcpy(&value, &bits, sizeof(float));
        return value;
    }
    
    double readDouble() {
        uint64_t bits = readU64();
        double value;
        std::memcpy(&value, &bits, sizeof(double));
        return value;
    }
    
    // Read string (null-terminated)
    std::string readString() {
        std::string result;
        while (m_pos < m_size && m_data[m_pos] != 0) {
            result += static_cast<char>(m_data[m_pos++]);
        }
        if (m_pos < m_size) m_pos++; // Skip null terminator
        return result;
    }
    
    // Read fixed-length string
    std::string readString(size_t length) {
        checkBounds(length);
        std::string result(reinterpret_cast<const char*>(m_data + m_pos), length);
        m_pos += length;
        // Remove null padding
        size_t nullPos = result.find('\0');
        if (nullPos != std::string::npos) {
            result.resize(nullPos);
        }
        return result;
    }
    
    // Read length-prefixed string
    std::string readLString() {
        uint16_t length = readU16();
        return readString(length);
    }
    
    // Read raw bytes
    std::vector<uint8_t> readBytes(size_t count) {
        checkBounds(count);
        std::vector<uint8_t> result(m_data + m_pos, m_data + m_pos + count);
        m_pos += count;
        return result;
    }
    
    // Skip bytes
    void skip(size_t count) {
        checkBounds(count);
        m_pos += count;
    }
    
    // Position
    size_t position() const { return m_pos; }
    size_t remaining() const { return m_size - m_pos; }
    bool hasMore() const { return m_pos < m_size; }
    
    void seek(size_t pos) {
        if (pos > m_size) {
            throw std::out_of_range("Seek position out of range");
        }
        m_pos = pos;
    }
    
private:
    void checkBounds(size_t count) const {
        if (m_pos + count > m_size) {
            throw std::out_of_range("Buffer read out of bounds");
        }
    }
    
    const uint8_t* m_data;
    size_t m_size;
    size_t m_pos;
};

/**
 * Buffer writer for building binary data
 */
class BufferWriter {
public:
    BufferWriter() {
        m_data.reserve(256);
    }
    
    explicit BufferWriter(size_t reserveSize) {
        m_data.reserve(reserveSize);
    }
    
    // Write primitives (little-endian)
    void writeU8(uint8_t value) {
        m_data.push_back(value);
    }
    
    void writeI8(int8_t value) {
        writeU8(static_cast<uint8_t>(value));
    }
    
    void writeU16(uint16_t value) {
        m_data.push_back(value & 0xFF);
        m_data.push_back((value >> 8) & 0xFF);
    }
    
    void writeI16(int16_t value) {
        writeU16(static_cast<uint16_t>(value));
    }
    
    void writeU32(uint32_t value) {
        m_data.push_back(value & 0xFF);
        m_data.push_back((value >> 8) & 0xFF);
        m_data.push_back((value >> 16) & 0xFF);
        m_data.push_back((value >> 24) & 0xFF);
    }
    
    void writeI32(int32_t value) {
        writeU32(static_cast<uint32_t>(value));
    }
    
    void writeU64(uint64_t value) {
        for (int i = 0; i < 8; i++) {
            m_data.push_back((value >> (i * 8)) & 0xFF);
        }
    }
    
    void writeI64(int64_t value) {
        writeU64(static_cast<uint64_t>(value));
    }
    
    void writeFloat(float value) {
        uint32_t bits;
        std::memcpy(&bits, &value, sizeof(float));
        writeU32(bits);
    }
    
    void writeDouble(double value) {
        uint64_t bits;
        std::memcpy(&bits, &value, sizeof(double));
        writeU64(bits);
    }
    
    // Write null-terminated string
    void writeString(const std::string& str) {
        m_data.insert(m_data.end(), str.begin(), str.end());
        m_data.push_back(0);
    }
    
    // Write fixed-length string (padded with nulls)
    void writeString(const std::string& str, size_t length) {
        size_t writeLen = std::min(str.size(), length);
        m_data.insert(m_data.end(), str.begin(), str.begin() + writeLen);
        for (size_t i = writeLen; i < length; i++) {
            m_data.push_back(0);
        }
    }
    
    // Write length-prefixed string
    void writeLString(const std::string& str) {
        writeU16(static_cast<uint16_t>(str.size()));
        m_data.insert(m_data.end(), str.begin(), str.end());
    }
    
    // Write raw bytes
    void writeBytes(const uint8_t* data, size_t count) {
        m_data.insert(m_data.end(), data, data + count);
    }
    
    void writeBytes(const std::vector<uint8_t>& data) {
        m_data.insert(m_data.end(), data.begin(), data.end());
    }
    
    // Pad with zeros
    void pad(size_t count) {
        m_data.insert(m_data.end(), count, 0);
    }
    
    // Get result
    const std::vector<uint8_t>& data() const { return m_data; }
    std::vector<uint8_t>&& take() { return std::move(m_data); }
    size_t size() const { return m_data.size(); }
    
    void clear() { m_data.clear(); }
    
private:
    std::vector<uint8_t> m_data;
};

} // namespace ds2
