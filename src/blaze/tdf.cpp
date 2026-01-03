#include "tdf.hpp"
#include <stdexcept>
#include <cstring>

namespace ds2 {
namespace blaze {

// Character set for Blaze label encoding (base-32ish)
// 0x20-0x5F maps to 0-63
static char labelCharset[] = " !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_";

uint32_t encodeLabel(const char* label) {
    uint32_t result = 0;
    for (int i = 0; i < 4 && label[i]; i++) {
        char c = label[i];
        if (c >= 'a' && c <= 'z') {
            c = c - 'a' + 'A';  // Convert to uppercase
        }
        uint8_t val = (c >= 0x20 && c <= 0x5F) ? (c - 0x20) : 0;
        result = (result << 6) | val;
    }
    return result;
}

std::string decodeLabel(uint32_t encoded) {
    std::string result;
    for (int i = 3; i >= 0; i--) {
        uint8_t val = (encoded >> (i * 6)) & 0x3F;
        char c = labelCharset[val];
        if (c != ' ') {
            result += c;
        }
    }
    return result;
}

// =============================================================================
// TdfWriter
// =============================================================================

TdfWriter::TdfWriter() {
    m_data.reserve(256);
}

void TdfWriter::encodeTag(const char* label, TdfType type) {
    uint32_t encoded = encodeLabel(label);
    // Tag is 3 bytes of label + 1 byte of type
    m_data.push_back((encoded >> 16) & 0xFF);
    m_data.push_back((encoded >> 8) & 0xFF);
    m_data.push_back(encoded & 0xFF);
    m_data.push_back(static_cast<uint8_t>(type));
}

void TdfWriter::encodeVarInt(uint64_t value) {
    // Variable-length integer encoding
    // Similar to LEB128 but big-endian with different continuation bit
    if (value < 0x40) {
        m_data.push_back(static_cast<uint8_t>(value));
    } else if (value < 0x4000) {
        m_data.push_back(0x80 | ((value >> 8) & 0x3F));
        m_data.push_back(value & 0xFF);
    } else if (value < 0x400000) {
        m_data.push_back(0xC0 | ((value >> 16) & 0x3F));
        m_data.push_back((value >> 8) & 0xFF);
        m_data.push_back(value & 0xFF);
    } else if (value < 0x40000000) {
        m_data.push_back(0xE0 | ((value >> 24) & 0x3F));
        m_data.push_back((value >> 16) & 0xFF);
        m_data.push_back((value >> 8) & 0xFF);
        m_data.push_back(value & 0xFF);
    } else {
        m_data.push_back(0xF0 | ((value >> 32) & 0x0F));
        m_data.push_back((value >> 24) & 0xFF);
        m_data.push_back((value >> 16) & 0xFF);
        m_data.push_back((value >> 8) & 0xFF);
        m_data.push_back(value & 0xFF);
    }
}

void TdfWriter::writeTag(const char* label, TdfType type) {
    encodeTag(label, type);
}

void TdfWriter::writeInteger(const char* label, int64_t value) {
    encodeTag(label, TdfType::Integer);
    writeInteger(value);
}

void TdfWriter::writeInteger(int64_t value) {
    // Handle negative numbers by converting to unsigned with zigzag encoding
    uint64_t uval = (value >= 0) ? (value << 1) : (((-value) << 1) - 1);
    encodeVarInt(uval);
}

void TdfWriter::writeString(const char* label, const std::string& value) {
    encodeTag(label, TdfType::String);
    writeString(value);
}

void TdfWriter::writeString(const std::string& value) {
    encodeVarInt(value.size() + 1);  // Include null terminator
    m_data.insert(m_data.end(), value.begin(), value.end());
    m_data.push_back(0);  // Null terminator
}

void TdfWriter::writeBlob(const char* label, const std::vector<uint8_t>& data) {
    encodeTag(label, TdfType::Binary);
    writeBlob(data);
}

void TdfWriter::writeBlob(const std::vector<uint8_t>& data) {
    encodeVarInt(data.size());
    m_data.insert(m_data.end(), data.begin(), data.end());
}

void TdfWriter::startStruct(const char* label) {
    encodeTag(label, TdfType::Struct);
}

void TdfWriter::endStruct() {
    m_data.push_back(0x00);  // Struct terminator
}

void TdfWriter::startList(const char* label, TdfType elementType, size_t count) {
    encodeTag(label, TdfType::List);
    m_data.push_back(static_cast<uint8_t>(elementType));
    encodeVarInt(count);
}

void TdfWriter::endList() {
    // Lists don't need explicit terminator - count is known
}

void TdfWriter::startMap(const char* label, TdfType keyType, TdfType valueType, size_t count) {
    encodeTag(label, TdfType::Map);
    m_data.push_back(static_cast<uint8_t>(keyType));
    m_data.push_back(static_cast<uint8_t>(valueType));
    encodeVarInt(count);
}

void TdfWriter::endMap() {
    // Maps don't need explicit terminator - count is known
}

void TdfWriter::writeUnion(const char* label, uint8_t activeField) {
    encodeTag(label, TdfType::Union);
    m_data.push_back(activeField);
}

void TdfWriter::writeObjectType(const char* label, uint16_t component, uint16_t type) {
    encodeTag(label, TdfType::ObjectType);
    m_data.push_back((component >> 8) & 0xFF);
    m_data.push_back(component & 0xFF);
    m_data.push_back((type >> 8) & 0xFF);
    m_data.push_back(type & 0xFF);
}

void TdfWriter::writeObjectId(const char* label, uint16_t component, uint16_t type, uint64_t id) {
    encodeTag(label, TdfType::ObjectId);
    m_data.push_back((component >> 8) & 0xFF);
    m_data.push_back(component & 0xFF);
    m_data.push_back((type >> 8) & 0xFF);
    m_data.push_back(type & 0xFF);
    encodeVarInt(id);
}

void TdfWriter::writeFloat(const char* label, float value) {
    encodeTag(label, TdfType::Float);
    uint32_t bits;
    std::memcpy(&bits, &value, sizeof(float));
    m_data.push_back((bits >> 24) & 0xFF);
    m_data.push_back((bits >> 16) & 0xFF);
    m_data.push_back((bits >> 8) & 0xFF);
    m_data.push_back(bits & 0xFF);
}

// =============================================================================
// TdfReader
// =============================================================================

TdfReader::TdfReader(const uint8_t* data, size_t size)
    : m_data(data), m_size(size), m_pos(0) {}

TdfReader::TdfReader(const std::vector<uint8_t>& data)
    : m_data(data.data()), m_size(data.size()), m_pos(0) {}

void TdfReader::checkBounds(size_t needed) {
    if (m_pos + needed > m_size) {
        throw std::out_of_range("TDF read out of bounds");
    }
}

uint64_t TdfReader::decodeVarInt() {
    checkBounds(1);
    uint8_t first = m_data[m_pos++];
    
    if ((first & 0xC0) == 0x00) {
        // 1 byte, 6 bits
        return first & 0x3F;
    } else if ((first & 0xC0) == 0x80) {
        // 2 bytes, 14 bits
        checkBounds(1);
        return ((first & 0x3F) << 8) | m_data[m_pos++];
    } else if ((first & 0xC0) == 0xC0 && (first & 0x20) == 0x00) {
        // 3 bytes, 22 bits
        checkBounds(2);
        uint64_t val = (first & 0x1F) << 16;
        val |= m_data[m_pos++] << 8;
        val |= m_data[m_pos++];
        return val;
    } else if ((first & 0xF0) == 0xE0) {
        // 4 bytes, 30 bits
        checkBounds(3);
        uint64_t val = (first & 0x0F) << 24;
        val |= m_data[m_pos++] << 16;
        val |= m_data[m_pos++] << 8;
        val |= m_data[m_pos++];
        return val;
    } else {
        // 5 bytes, 38 bits
        checkBounds(4);
        uint64_t val = static_cast<uint64_t>(first & 0x0F) << 32;
        val |= static_cast<uint64_t>(m_data[m_pos++]) << 24;
        val |= m_data[m_pos++] << 16;
        val |= m_data[m_pos++] << 8;
        val |= m_data[m_pos++];
        return val;
    }
}

bool TdfReader::readTag(std::string& label, TdfType& type) {
    if (m_pos >= m_size) {
        return false;
    }
    
    // Check for struct terminator
    if (m_data[m_pos] == 0x00) {
        m_pos++;
        label = "";
        type = TdfType::Invalid;
        return false;
    }
    
    checkBounds(4);
    uint32_t encoded = (m_data[m_pos] << 16) | (m_data[m_pos + 1] << 8) | m_data[m_pos + 2];
    label = decodeLabel(encoded);
    type = static_cast<TdfType>(m_data[m_pos + 3]);
    m_pos += 4;
    
    return true;
}

int64_t TdfReader::readInteger() {
    uint64_t uval = decodeVarInt();
    // Zigzag decode
    return (uval >> 1) ^ (-(uval & 1));
}

uint64_t TdfReader::readUInteger() {
    return decodeVarInt();
}

std::string TdfReader::readString() {
    size_t len = decodeVarInt();
    if (len == 0) return "";
    
    checkBounds(len);
    std::string result(reinterpret_cast<const char*>(m_data + m_pos), len - 1);  // Exclude null
    m_pos += len;
    return result;
}

std::vector<uint8_t> TdfReader::readBlob() {
    size_t len = decodeVarInt();
    checkBounds(len);
    std::vector<uint8_t> result(m_data + m_pos, m_data + m_pos + len);
    m_pos += len;
    return result;
}

void TdfReader::readListHeader(TdfType& elementType, size_t& count) {
    checkBounds(1);
    elementType = static_cast<TdfType>(m_data[m_pos++]);
    count = decodeVarInt();
}

void TdfReader::readMapHeader(TdfType& keyType, TdfType& valueType, size_t& count) {
    checkBounds(2);
    keyType = static_cast<TdfType>(m_data[m_pos++]);
    valueType = static_cast<TdfType>(m_data[m_pos++]);
    count = decodeVarInt();
}

void TdfReader::readStructStart() {
    // Struct doesn't have an explicit start marker after tag
}

void TdfReader::readStructEnd() {
    checkBounds(1);
    if (m_data[m_pos] != 0x00) {
        throw std::runtime_error("Expected struct terminator");
    }
    m_pos++;
}

uint8_t TdfReader::readUnion() {
    checkBounds(1);
    return m_data[m_pos++];
}

void TdfReader::readObjectType(uint16_t& component, uint16_t& type) {
    checkBounds(4);
    component = (m_data[m_pos] << 8) | m_data[m_pos + 1];
    type = (m_data[m_pos + 2] << 8) | m_data[m_pos + 3];
    m_pos += 4;
}

void TdfReader::readObjectId(uint16_t& component, uint16_t& type, uint64_t& id) {
    checkBounds(4);
    component = (m_data[m_pos] << 8) | m_data[m_pos + 1];
    type = (m_data[m_pos + 2] << 8) | m_data[m_pos + 3];
    m_pos += 4;
    id = decodeVarInt();
}

float TdfReader::readFloat() {
    checkBounds(4);
    uint32_t bits = (m_data[m_pos] << 24) | (m_data[m_pos + 1] << 16) |
                    (m_data[m_pos + 2] << 8) | m_data[m_pos + 3];
    m_pos += 4;
    float value;
    std::memcpy(&value, &bits, sizeof(float));
    return value;
}

void TdfReader::skipValue(TdfType type) {
    switch (type) {
        case TdfType::Integer:
            decodeVarInt();
            break;
        case TdfType::String:
        case TdfType::Binary: {
            size_t len = decodeVarInt();
            checkBounds(len);
            m_pos += len;
            break;
        }
        case TdfType::Struct: {
            std::string label;
            TdfType fieldType;
            while (readTag(label, fieldType)) {
                skipValue(fieldType);
            }
            break;
        }
        case TdfType::List: {
            TdfType elemType;
            size_t count;
            readListHeader(elemType, count);
            for (size_t i = 0; i < count; i++) {
                skipValue(elemType);
            }
            break;
        }
        case TdfType::Map: {
            TdfType keyType, valType;
            size_t count;
            readMapHeader(keyType, valType, count);
            for (size_t i = 0; i < count; i++) {
                skipValue(keyType);
                skipValue(valType);
            }
            break;
        }
        case TdfType::Union: {
            uint8_t activeField = readUnion();
            if (activeField != 0x7F) {  // 0x7F means unset union
                // Read the union value - we need to parse the nested tag
                std::string label;
                TdfType fieldType;
                if (readTag(label, fieldType)) {
                    skipValue(fieldType);
                }
            }
            break;
        }
        case TdfType::ObjectType:
            checkBounds(4);
            m_pos += 4;
            break;
        case TdfType::ObjectId:
            checkBounds(4);
            m_pos += 4;
            decodeVarInt();
            break;
        case TdfType::Float:
            checkBounds(4);
            m_pos += 4;
            break;
        case TdfType::TimeValue:
            decodeVarInt();
            break;
        default:
            throw std::runtime_error("Unknown TDF type");
    }
}

} // namespace blaze
} // namespace ds2
