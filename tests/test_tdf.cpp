#include "test_framework.hpp"
#include "blaze/tdf.hpp"
#include "blaze/blaze_types.hpp"

using namespace ds2::blaze;
using namespace ds2::test;

// =============================================================================
// Label Encoding Tests
// =============================================================================

TEST(TDF_LabelEncode_Simple) {
    // Test encoding a 4-char label
    uint32_t encoded = encodeLabel("TEST");
    std::string decoded = decodeLabel(encoded);
    ASSERT_STREQ(decoded.c_str(), "TEST");
    PASS();
}

TEST(TDF_LabelEncode_Short) {
    // Test encoding shorter labels (padded with spaces)
    uint32_t encoded = encodeLabel("AB");
    std::string decoded = decodeLabel(encoded);
    // Decoded may have padding - just verify it starts with AB
    ASSERT_TRUE(decoded.substr(0, 2) == "AB");
    PASS();
}

TEST(TDF_LabelEncode_AllChars) {
    // Test various valid labels
    const char* labels[] = {"ADDR", "PORT", "NAME", "DATA", "USER", "PASS"};
    for (const char* label : labels) {
        uint32_t encoded = encodeLabel(label);
        std::string decoded = decodeLabel(encoded);
        ASSERT_STREQ(decoded.c_str(), label);
    }
    PASS();
}

// =============================================================================
// TdfWriter/Reader Integer Tests
// =============================================================================

TEST(TDF_Integer_Small) {
    TdfWriter writer;
    writer.writeInteger("IVAL", 42);
    auto data = writer.take();
    
    TdfReader reader(data);
    std::string label;
    TdfType type;
    ASSERT_TRUE(reader.readTag(label, type));
    ASSERT_STREQ(label.c_str(), "IVAL");
    ASSERT_TRUE(type == TdfType::Integer);
    
    int64_t value = reader.readInteger();
    ASSERT_EQ(value, 42);
    PASS();
}

TEST(TDF_Integer_Negative) {
    TdfWriter writer;
    writer.writeInteger("NEGV", -100);
    auto data = writer.take();
    
    TdfReader reader(data);
    std::string label;
    TdfType type;
    ASSERT_TRUE(reader.readTag(label, type));
    
    int64_t value = reader.readInteger();
    ASSERT_EQ(value, -100);
    PASS();
}

TEST(TDF_Integer_Large) {
    TdfWriter writer;
    writer.writeInteger("BIG ", 1000000000LL);
    auto data = writer.take();
    
    TdfReader reader(data);
    std::string label;
    TdfType type;
    ASSERT_TRUE(reader.readTag(label, type));
    
    int64_t value = reader.readInteger();
    ASSERT_EQ(value, 1000000000LL);
    PASS();
}

TEST(TDF_Integer_Zero) {
    TdfWriter writer;
    writer.writeInteger("ZERO", 0);
    auto data = writer.take();
    
    TdfReader reader(data);
    std::string label;
    TdfType type;
    ASSERT_TRUE(reader.readTag(label, type));
    
    int64_t value = reader.readInteger();
    ASSERT_EQ(value, 0);
    PASS();
}

// =============================================================================
// TdfWriter/Reader String Tests
// =============================================================================

TEST(TDF_String_Simple) {
    TdfWriter writer;
    writer.writeString("NAME", "Hello World");
    auto data = writer.take();
    
    TdfReader reader(data);
    std::string label;
    TdfType type;
    ASSERT_TRUE(reader.readTag(label, type));
    ASSERT_STREQ(label.c_str(), "NAME");
    ASSERT_TRUE(type == TdfType::String);
    
    std::string value = reader.readString();
    ASSERT_STREQ(value.c_str(), "Hello World");
    PASS();
}

TEST(TDF_String_Empty) {
    TdfWriter writer;
    writer.writeString("EMTY", "");
    auto data = writer.take();
    
    TdfReader reader(data);
    std::string label;
    TdfType type;
    ASSERT_TRUE(reader.readTag(label, type));
    
    std::string value = reader.readString();
    ASSERT_STREQ(value.c_str(), "");
    PASS();
}

TEST(TDF_String_Long) {
    std::string longStr(1000, 'X');  // 1000 'X' characters
    
    TdfWriter writer;
    writer.writeString("LONG", longStr);
    auto data = writer.take();
    
    TdfReader reader(data);
    std::string label;
    TdfType type;
    ASSERT_TRUE(reader.readTag(label, type));
    
    std::string value = reader.readString();
    ASSERT_EQ(value.length(), 1000u);
    ASSERT_STREQ(value.c_str(), longStr.c_str());
    PASS();
}

// =============================================================================
// TdfWriter/Reader Blob Tests
// =============================================================================

TEST(TDF_Blob_Simple) {
    std::vector<uint8_t> blob = {0x01, 0x02, 0x03, 0x04, 0x05};
    
    TdfWriter writer;
    writer.writeBlob("BLOB", blob);
    auto data = writer.take();
    
    TdfReader reader(data);
    std::string label;
    TdfType type;
    ASSERT_TRUE(reader.readTag(label, type));
    ASSERT_TRUE(type == TdfType::Binary);
    
    auto readBlob = reader.readBlob();
    ASSERT_EQ(readBlob.size(), blob.size());
    for (size_t i = 0; i < blob.size(); i++) {
        if (readBlob[i] != blob[i]) {
            _msg = "Blob mismatch at index " + std::to_string(i);
            return false;
        }
    }
    PASS();
}

TEST(TDF_Blob_Empty) {
    std::vector<uint8_t> blob;
    
    TdfWriter writer;
    writer.writeBlob("EMTY", blob);
    auto data = writer.take();
    
    TdfReader reader(data);
    std::string label;
    TdfType type;
    ASSERT_TRUE(reader.readTag(label, type));
    
    auto readBlob = reader.readBlob();
    ASSERT_EQ(readBlob.size(), 0u);
    PASS();
}

// =============================================================================
// TdfWriter/Reader Struct Tests
// =============================================================================

TEST(TDF_Struct_Simple) {
    TdfWriter writer;
    writer.startStruct("USER");
    writer.writeString("NAME", "Player1");
    writer.writeInteger("LVL ", 50);
    writer.endStruct();
    auto data = writer.take();
    
    TdfReader reader(data);
    std::string label;
    TdfType type;
    
    // Read struct tag
    ASSERT_TRUE(reader.readTag(label, type));
    ASSERT_STREQ(label.c_str(), "USER");
    ASSERT_TRUE(type == TdfType::Struct);
    
    // Read fields inside struct
    ASSERT_TRUE(reader.readTag(label, type));
    ASSERT_STREQ(label.c_str(), "NAME");
    std::string name = reader.readString();
    ASSERT_STREQ(name.c_str(), "Player1");
    
    ASSERT_TRUE(reader.readTag(label, type));
    int64_t level = reader.readInteger();
    ASSERT_EQ(level, 50);
    
    PASS();
}

// =============================================================================
// TdfWriter/Reader List Tests
// =============================================================================

TEST(TDF_List_Integers) {
    TdfWriter writer;
    writer.startList("NUMS", TdfType::Integer, 3);
    writer.writeInteger(10);
    writer.writeInteger(20);
    writer.writeInteger(30);
    writer.endList();
    auto data = writer.take();
    
    TdfReader reader(data);
    std::string label;
    TdfType type;
    
    ASSERT_TRUE(reader.readTag(label, type));
    ASSERT_STREQ(label.c_str(), "NUMS");
    ASSERT_TRUE(type == TdfType::List);
    
    TdfType elemType;
    size_t count;
    reader.readListHeader(elemType, count);
    ASSERT_TRUE(elemType == TdfType::Integer);
    ASSERT_EQ(count, 3u);
    
    ASSERT_EQ(reader.readInteger(), 10);
    ASSERT_EQ(reader.readInteger(), 20);
    ASSERT_EQ(reader.readInteger(), 30);
    
    PASS();
}

TEST(TDF_List_Strings) {
    TdfWriter writer;
    writer.startList("STRS", TdfType::String, 2);
    writer.writeString("First");
    writer.writeString("Second");
    writer.endList();
    auto data = writer.take();
    
    TdfReader reader(data);
    std::string label;
    TdfType type;
    
    ASSERT_TRUE(reader.readTag(label, type));
    
    TdfType elemType;
    size_t count;
    reader.readListHeader(elemType, count);
    ASSERT_EQ(count, 2u);
    
    ASSERT_STREQ(reader.readString().c_str(), "First");
    ASSERT_STREQ(reader.readString().c_str(), "Second");
    
    PASS();
}

// =============================================================================
// TdfWriter/Reader Map Tests
// =============================================================================

TEST(TDF_Map_StringToInt) {
    TdfWriter writer;
    writer.startMap("SMAP", TdfType::String, TdfType::Integer, 2);
    writer.writeString("key1");
    writer.writeInteger(100);
    writer.writeString("key2");
    writer.writeInteger(200);
    writer.endMap();
    auto data = writer.take();
    
    TdfReader reader(data);
    std::string label;
    TdfType type;
    
    ASSERT_TRUE(reader.readTag(label, type));
    ASSERT_TRUE(type == TdfType::Map);
    
    TdfType keyType, valueType;
    size_t count;
    reader.readMapHeader(keyType, valueType, count);
    ASSERT_TRUE(keyType == TdfType::String);
    ASSERT_TRUE(valueType == TdfType::Integer);
    ASSERT_EQ(count, 2u);
    
    ASSERT_STREQ(reader.readString().c_str(), "key1");
    ASSERT_EQ(reader.readInteger(), 100);
    ASSERT_STREQ(reader.readString().c_str(), "key2");
    ASSERT_EQ(reader.readInteger(), 200);
    
    PASS();
}

// =============================================================================
// Complex/Integration Tests
// =============================================================================

TEST(TDF_Complex_PlayerInfo) {
    // Simulate a realistic player info structure
    TdfWriter writer;
    writer.startStruct("PINF");
    writer.writeInteger("PID ", 123456);
    writer.writeString("NAME", "DeadSpacePlayer");
    writer.writeInteger("LVL ", 25);
    writer.startStruct("STAT");
    writer.writeInteger("KILL", 1500);
    writer.writeInteger("DETH", 300);
    writer.writeInteger("ASST", 800);
    writer.endStruct();
    writer.startList("GEAR", TdfType::Integer, 3);
    writer.writeInteger(1);  // Weapon ID
    writer.writeInteger(2);  // Armor ID
    writer.writeInteger(3);  // Module ID
    writer.endList();
    writer.endStruct();
    
    auto data = writer.take();
    
    // Verify we can read it back
    TdfReader reader(data);
    std::string label;
    TdfType type;
    
    ASSERT_TRUE(reader.readTag(label, type));
    ASSERT_STREQ(label.c_str(), "PINF");
    ASSERT_TRUE(type == TdfType::Struct);
    
    // Read PID (label may be trimmed to "PID" without trailing space)
    ASSERT_TRUE(reader.readTag(label, type));
    ASSERT_TRUE(label == "PID " || label == "PID");
    ASSERT_EQ(reader.readInteger(), 123456);
    
    // Read NAME
    ASSERT_TRUE(reader.readTag(label, type));
    ASSERT_STREQ(label.c_str(), "NAME");
    ASSERT_STREQ(reader.readString().c_str(), "DeadSpacePlayer");
    
    PASS();
}

TEST(TDF_MultipleFields) {
    TdfWriter writer;
    writer.writeInteger("FLD1", 1);
    writer.writeInteger("FLD2", 2);
    writer.writeInteger("FLD3", 3);
    writer.writeString("FLD4", "test");
    writer.writeInteger("FLD5", 5);
    auto data = writer.take();
    
    TdfReader reader(data);
    std::string label;
    TdfType type;
    
    ASSERT_TRUE(reader.readTag(label, type));
    ASSERT_STREQ(label.c_str(), "FLD1");
    ASSERT_EQ(reader.readInteger(), 1);
    
    ASSERT_TRUE(reader.readTag(label, type));
    ASSERT_EQ(reader.readInteger(), 2);
    
    ASSERT_TRUE(reader.readTag(label, type));
    ASSERT_EQ(reader.readInteger(), 3);
    
    ASSERT_TRUE(reader.readTag(label, type));
    ASSERT_STREQ(reader.readString().c_str(), "test");
    
    ASSERT_TRUE(reader.readTag(label, type));
    ASSERT_EQ(reader.readInteger(), 5);
    
    PASS();
}
