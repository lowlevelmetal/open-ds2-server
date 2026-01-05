#include "blaze/tdf.hpp"
#include "utils/logger.hpp"
#include <cstring>
#include <stdexcept>

namespace ds2::blaze {

// =============================================================================
// TDF Tag Encoding
// =============================================================================
// Tag character to 6-bit value mapping:
//   ' ' (space) = 0
//   'A'-'Z' = 1-26
//   '0'-'9' = 27-36
//   '_' = 37

static uint8_t charToTagValue(char c) {
    if (c == ' ' || c == '\0') return 0;
    if (c >= 'A' && c <= 'Z') return c - 'A' + 1;
    if (c >= 'a' && c <= 'z') return c - 'a' + 1;  // Treat lowercase as uppercase
    if (c >= '0' && c <= '9') return c - '0' + 27;
    if (c == '_') return 37;
    return 0;  // Unknown char maps to space
}

static char tagValueToChar(uint8_t v) {
    if (v == 0) return ' ';
    if (v >= 1 && v <= 26) return 'A' + v - 1;
    if (v >= 27 && v <= 36) return '0' + v - 27;
    if (v == 37) return '_';
    return ' ';
}

// =============================================================================
// TdfEncoder Implementation
// =============================================================================

TdfEncoder::TdfEncoder() {
    m_buffer.reserve(256);
}

std::vector<uint8_t> TdfEncoder::encode(const TdfStruct& data) {
    m_buffer.clear();
    
    for (const auto& [tag, value] : data) {
        if (!value) continue;
        
        switch (value->type) {
            case TdfType::Integer:
                encodeInteger(value->tag, std::get<TdfInteger>(value->value));
                break;
            case TdfType::String:
                encodeString(value->tag, std::get<TdfString>(value->value));
                break;
            case TdfType::Binary:
                encodeBinary(value->tag, std::get<TdfBinary>(value->value));
                break;
            case TdfType::Struct:
                encodeStruct(value->tag, std::get<TdfStruct>(value->value));
                break;
            case TdfType::List:
                encodeList(value->tag, TdfType::Struct, std::get<TdfList>(value->value));
                break;
            case TdfType::IntList:
                encodeIntList(value->tag, std::get<TdfIntList>(value->value));
                break;
            case TdfType::Pair:
                encodePair(value->tag, std::get<TdfPair>(value->value));
                break;
            case TdfType::Triple:
                encodeTriple(value->tag, std::get<TdfTriple>(value->value));
                break;
            case TdfType::Float:
                encodeFloat(value->tag, std::get<float>(value->value));
                break;
            default:
                break;
        }
    }
    
    // Struct terminator
    writeByte(0x00);
    
    return m_buffer;
}

void TdfEncoder::encodeTag(const std::string& tag) {
    // Pad or truncate tag to 4 characters
    std::string t = tag;
    while (t.size() < 4) t += ' ';
    if (t.size() > 4) t = t.substr(0, 4);
    
    // Convert 4 chars to 3 bytes (6 bits each)
    uint8_t v0 = charToTagValue(t[0]);
    uint8_t v1 = charToTagValue(t[1]);
    uint8_t v2 = charToTagValue(t[2]);
    uint8_t v3 = charToTagValue(t[3]);
    
    // Pack: [v0:6][v1[5:4]:2] [v1[3:0]:4][v2[5:2]:4] [v2[1:0]:2][v3:6]
    writeByte((v0 << 2) | (v1 >> 4));
    writeByte(((v1 & 0x0F) << 4) | (v2 >> 2));
    writeByte(((v2 & 0x03) << 6) | v3);
}

void TdfEncoder::encodeVarInt(int64_t value) {
    // Zigzag encoding for signed integers
    uint64_t encoded = (value << 1) ^ (value >> 63);
    encodeVarUInt(encoded);
}

void TdfEncoder::encodeVarUInt(uint64_t value) {
    // Variable-length encoding: 7 bits per byte, high bit = continuation
    do {
        uint8_t byte = value & 0x7F;
        value >>= 7;
        if (value != 0) {
            byte |= 0x80;
        }
        writeByte(byte);
    } while (value != 0);
}

void TdfEncoder::encodeInteger(const std::string& tag, int64_t value) {
    encodeTag(tag);
    writeByte(static_cast<uint8_t>(TdfType::Integer));
    encodeVarInt(value);
}

void TdfEncoder::encodeString(const std::string& tag, const std::string& value) {
    encodeTag(tag);
    writeByte(static_cast<uint8_t>(TdfType::String));
    encodeVarUInt(value.size() + 1);  // +1 for null terminator
    writeBytes(value.c_str(), value.size() + 1);
}

void TdfEncoder::encodeBinary(const std::string& tag, const std::vector<uint8_t>& value) {
    encodeTag(tag);
    writeByte(static_cast<uint8_t>(TdfType::Binary));
    encodeVarUInt(value.size());
    writeBytes(value.data(), value.size());
}

void TdfEncoder::encodeStruct(const std::string& tag, const TdfStruct& value) {
    encodeTag(tag);
    writeByte(static_cast<uint8_t>(TdfType::Struct));
    
    // Encode struct contents
    for (const auto& [childTag, childValue] : value) {
        if (!childValue) continue;
        
        switch (childValue->type) {
            case TdfType::Integer:
                encodeInteger(childValue->tag, std::get<TdfInteger>(childValue->value));
                break;
            case TdfType::String:
                encodeString(childValue->tag, std::get<TdfString>(childValue->value));
                break;
            case TdfType::Struct:
                encodeStruct(childValue->tag, std::get<TdfStruct>(childValue->value));
                break;
            case TdfType::Pair:
                encodePair(childValue->tag, std::get<TdfPair>(childValue->value));
                break;
            case TdfType::Triple:
                encodeTriple(childValue->tag, std::get<TdfTriple>(childValue->value));
                break;
            default:
                break;
        }
    }
    
    // Struct terminator
    writeByte(0x00);
}

void TdfEncoder::encodeList(const std::string& tag, TdfType elementType, const TdfList& value) {
    encodeTag(tag);
    writeByte(static_cast<uint8_t>(TdfType::List));
    writeByte(static_cast<uint8_t>(elementType));
    encodeVarUInt(value.size());
    
    // Encode list elements
    for (const auto& elem : value) {
        if (!elem) continue;
        
        if (elem->type == TdfType::Struct) {
            // For struct elements, encode contents directly without tag
            const auto& s = std::get<TdfStruct>(elem->value);
            for (const auto& [childTag, childValue] : s) {
                if (!childValue) continue;
                
                switch (childValue->type) {
                    case TdfType::Integer:
                        encodeInteger(childValue->tag, std::get<TdfInteger>(childValue->value));
                        break;
                    case TdfType::String:
                        encodeString(childValue->tag, std::get<TdfString>(childValue->value));
                        break;
                    default:
                        break;
                }
            }
            writeByte(0x00);  // Struct terminator
        }
    }
}

void TdfEncoder::encodeMap(const std::string& tag, TdfType keyType, TdfType valueType, const TdfMapWrapper& value) {
    encodeTag(tag);
    writeByte(static_cast<uint8_t>(TdfType::Map));
    writeByte(static_cast<uint8_t>(keyType));
    writeByte(static_cast<uint8_t>(valueType));
    encodeVarUInt(value.data.size());
    
    // TODO: Encode map entries
}

void TdfEncoder::encodeIntList(const std::string& tag, const TdfIntList& value) {
    encodeTag(tag);
    writeByte(static_cast<uint8_t>(TdfType::IntList));
    encodeVarUInt(value.size());
    
    for (int64_t v : value) {
        encodeVarInt(v);
    }
}

void TdfEncoder::encodePair(const std::string& tag, const TdfPair& value) {
    encodeTag(tag);
    writeByte(static_cast<uint8_t>(TdfType::Pair));
    encodeVarUInt(static_cast<uint64_t>(value.first));
    encodeVarUInt(static_cast<uint64_t>(value.second));
}

void TdfEncoder::encodeTriple(const std::string& tag, const TdfTriple& value) {
    encodeTag(tag);
    writeByte(static_cast<uint8_t>(TdfType::Triple));
    encodeVarUInt(value.ip);
    encodeVarUInt(value.port);
    encodeVarUInt(value.protocol);
}

void TdfEncoder::encodeFloat(const std::string& tag, float value) {
    encodeTag(tag);
    writeByte(static_cast<uint8_t>(TdfType::Float));
    writeBytes(&value, sizeof(float));
}

void TdfEncoder::writeBytes(const void* data, size_t size) {
    const uint8_t* p = static_cast<const uint8_t*>(data);
    m_buffer.insert(m_buffer.end(), p, p + size);
}

void TdfEncoder::writeByte(uint8_t byte) {
    m_buffer.push_back(byte);
}

// =============================================================================
// TdfDecoder Implementation
// =============================================================================

TdfDecoder::TdfDecoder(const std::vector<uint8_t>& data)
    : m_data(data.data()), m_size(data.size()), m_pos(0) {}

TdfDecoder::TdfDecoder(const uint8_t* data, size_t size)
    : m_data(data), m_size(size), m_pos(0) {}

TdfStruct TdfDecoder::decode() {
    TdfStruct result;
    
    while (hasMore()) {
        // Check for struct terminator
        if (m_data[m_pos] == 0x00) {
            m_pos++;
            break;
        }
        
        std::string tag = decodeTag();
        TdfType type = decodeType();
        
        auto value = std::make_shared<TdfValue>();
        value->tag = tag;
        value->type = type;
        
        switch (type) {
            case TdfType::Integer:
                value->value = decodeInteger();
                break;
            case TdfType::String:
                value->value = decodeString();
                break;
            case TdfType::Binary:
                value->value = decodeBinary();
                break;
            case TdfType::Struct:
                value->value = decodeStruct();
                break;
            case TdfType::List:
                value->value = decodeList();
                break;
            case TdfType::Map:
                value->value = decodeMap();
                break;
            case TdfType::IntList:
                value->value = decodeIntList();
                break;
            case TdfType::Pair:
                value->value = decodePair();
                break;
            case TdfType::Triple:
                value->value = decodeTriple();
                break;
            case TdfType::Float:
                value->value = decodeFloat();
                break;
            default:
                LOG_WARN("Unknown TDF type: {}", static_cast<int>(type));
                break;
        }
        
        result[tag] = value;
    }
    
    return result;
}

std::string TdfDecoder::decodeTag() {
    if (m_pos + 3 > m_size) {
        throw std::runtime_error("TDF: Not enough data for tag");
    }
    
    uint8_t b0 = readByte();
    uint8_t b1 = readByte();
    uint8_t b2 = readByte();
    
    // Unpack: 3 bytes -> 4 x 6-bit values
    uint8_t v0 = b0 >> 2;
    uint8_t v1 = ((b0 & 0x03) << 4) | (b1 >> 4);
    uint8_t v2 = ((b1 & 0x0F) << 2) | (b2 >> 6);
    uint8_t v3 = b2 & 0x3F;
    
    std::string tag;
    tag += tagValueToChar(v0);
    tag += tagValueToChar(v1);
    tag += tagValueToChar(v2);
    tag += tagValueToChar(v3);
    
    // Trim trailing spaces
    while (!tag.empty() && tag.back() == ' ') {
        tag.pop_back();
    }
    
    return tag;
}

TdfType TdfDecoder::decodeType() {
    return static_cast<TdfType>(readByte());
}

int64_t TdfDecoder::decodeVarInt() {
    uint64_t encoded = decodeVarUInt();
    // Zigzag decode
    return static_cast<int64_t>((encoded >> 1) ^ -(encoded & 1));
}

uint64_t TdfDecoder::decodeVarUInt() {
    uint64_t result = 0;
    int shift = 0;
    
    while (hasMore()) {
        uint8_t byte = readByte();
        result |= static_cast<uint64_t>(byte & 0x7F) << shift;
        
        if ((byte & 0x80) == 0) {
            break;
        }
        
        shift += 7;
        if (shift > 63) {
            throw std::runtime_error("TDF: VarInt too large");
        }
    }
    
    return result;
}

TdfInteger TdfDecoder::decodeInteger() {
    return decodeVarInt();
}

TdfString TdfDecoder::decodeString() {
    uint64_t length = decodeVarUInt();
    if (m_pos + length > m_size) {
        throw std::runtime_error("TDF: Not enough data for string");
    }
    
    std::string result(reinterpret_cast<const char*>(m_data + m_pos), length - 1);  // -1 for null
    m_pos += length;
    return result;
}

TdfBinary TdfDecoder::decodeBinary() {
    uint64_t length = decodeVarUInt();
    if (m_pos + length > m_size) {
        throw std::runtime_error("TDF: Not enough data for binary");
    }
    
    TdfBinary result(m_data + m_pos, m_data + m_pos + length);
    m_pos += length;
    return result;
}

TdfStruct TdfDecoder::decodeStruct() {
    return decode();  // Recursively decode struct contents
}

TdfList TdfDecoder::decodeList() {
    TdfType elementType = decodeType();
    uint64_t count = decodeVarUInt();
    
    TdfList result;
    result.reserve(count);
    
    for (uint64_t i = 0; i < count; i++) {
        auto elem = std::make_shared<TdfValue>();
        elem->type = elementType;
        
        switch (elementType) {
            case TdfType::Integer:
                elem->value = decodeInteger();
                break;
            case TdfType::String:
                elem->value = decodeString();
                break;
            case TdfType::Struct:
                elem->value = decodeStruct();
                break;
            default:
                break;
        }
        
        result.push_back(elem);
    }
    
    return result;
}

TdfMapWrapper TdfDecoder::decodeMap() {
    TdfType keyType = decodeType();
    TdfType valueType = decodeType();
    uint64_t count = decodeVarUInt();
    
    TdfMapWrapper result;
    
    // TODO: Properly decode map entries based on key/value types
    // For now, skip the data
    (void)keyType;
    (void)valueType;
    (void)count;
    
    return result;
}

TdfIntList TdfDecoder::decodeIntList() {
    uint64_t count = decodeVarUInt();
    
    TdfIntList result;
    result.reserve(count);
    
    for (uint64_t i = 0; i < count; i++) {
        result.push_back(decodeVarInt());
    }
    
    return result;
}

TdfPair TdfDecoder::decodePair() {
    TdfPair result;
    result.first = static_cast<int64_t>(decodeVarUInt());
    result.second = static_cast<int64_t>(decodeVarUInt());
    return result;
}

TdfTriple TdfDecoder::decodeTriple() {
    TdfTriple result;
    result.ip = static_cast<uint32_t>(decodeVarUInt());
    result.port = static_cast<uint16_t>(decodeVarUInt());
    result.protocol = static_cast<uint16_t>(decodeVarUInt());
    return result;
}

float TdfDecoder::decodeFloat() {
    float result;
    readBytes(&result, sizeof(float));
    return result;
}

uint8_t TdfDecoder::readByte() {
    if (m_pos >= m_size) {
        throw std::runtime_error("TDF: Unexpected end of data");
    }
    return m_data[m_pos++];
}

void TdfDecoder::readBytes(void* dest, size_t size) {
    if (m_pos + size > m_size) {
        throw std::runtime_error("TDF: Not enough data");
    }
    std::memcpy(dest, m_data + m_pos, size);
    m_pos += size;
}

// =============================================================================
// TdfBuilder Implementation
// =============================================================================

TdfStruct& TdfBuilder::current() {
    if (m_stack.empty()) {
        return m_root;
    }
    return *m_stack.back();
}

TdfBuilder& TdfBuilder::integer(const std::string& tag, int64_t value) {
    auto tdf = std::make_shared<TdfValue>(tag, TdfType::Integer, value);
    current()[tag] = tdf;
    return *this;
}

TdfBuilder& TdfBuilder::string(const std::string& tag, const std::string& value) {
    auto tdf = std::make_shared<TdfValue>(tag, TdfType::String, value);
    current()[tag] = tdf;
    return *this;
}

TdfBuilder& TdfBuilder::binary(const std::string& tag, const std::vector<uint8_t>& value) {
    auto tdf = std::make_shared<TdfValue>(tag, TdfType::Binary, value);
    current()[tag] = tdf;
    return *this;
}

TdfBuilder& TdfBuilder::pair(const std::string& tag, int64_t first, int64_t second) {
    TdfPair p{first, second};
    auto tdf = std::make_shared<TdfValue>(tag, TdfType::Pair, p);
    current()[tag] = tdf;
    return *this;
}

TdfBuilder& TdfBuilder::triple(const std::string& tag, uint32_t ip, uint16_t port, uint16_t protocol) {
    TdfTriple t{ip, port, protocol};
    auto tdf = std::make_shared<TdfValue>(tag, TdfType::Triple, t);
    current()[tag] = tdf;
    return *this;
}

TdfBuilder& TdfBuilder::intList(const std::string& tag, const std::vector<int64_t>& values) {
    auto tdf = std::make_shared<TdfValue>(tag, TdfType::IntList, values);
    current()[tag] = tdf;
    return *this;
}

TdfBuilder& TdfBuilder::beginStruct(const std::string& tag) {
    auto tdf = std::make_shared<TdfValue>();
    tdf->tag = tag;
    tdf->type = TdfType::Struct;
    tdf->value = TdfStruct{};
    
    current()[tag] = tdf;
    m_stack.push_back(&std::get<TdfStruct>(tdf->value));
    m_tagStack.push_back(tag);
    
    return *this;
}

TdfBuilder& TdfBuilder::endStruct() {
    if (!m_stack.empty()) {
        m_stack.pop_back();
        m_tagStack.pop_back();
    }
    return *this;
}

TdfStruct TdfBuilder::build() {
    return m_root;
}

std::vector<uint8_t> TdfBuilder::encode() {
    TdfEncoder encoder;
    return encoder.encode(m_root);
}

} // namespace ds2::blaze
