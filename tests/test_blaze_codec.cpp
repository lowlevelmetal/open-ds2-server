#include "test_framework.hpp"
#include "blaze/blaze_codec.hpp"
#include "blaze/blaze_types.hpp"
#include "blaze/tdf.hpp"

using namespace ds2::blaze;
using namespace ds2::test;

// =============================================================================
// Packet Encoding Tests
// =============================================================================

TEST(BlazePacket_EncodeEmpty) {
    Packet packet;
    packet.component = ComponentId::Redirector;
    packet.command = static_cast<uint16_t>(RedirectorCommand::GetServerInstance);
    packet.errorCode = 0;
    packet.type = PacketType::Message;
    packet.msgId = 1;
    
    auto data = BlazeCodec::encode(packet);
    
    // Header is 12 bytes minimum
    ASSERT_TRUE(data.size() >= 12);
    PASS();
}

TEST(BlazePacket_EncodeWithPayload) {
    Packet packet;
    packet.component = ComponentId::Authentication;
    packet.command = static_cast<uint16_t>(AuthCommand::Login);
    packet.errorCode = 0;
    packet.type = PacketType::Message;
    packet.msgId = 42;
    
    TdfWriter writer;
    writer.writeString("MAIL", "test@example.com");
    writer.writeString("PASS", "password123");
    packet.payload = writer.take();
    
    auto data = BlazeCodec::encode(packet);
    
    // Header + payload
    ASSERT_TRUE(data.size() > 12);
    ASSERT_EQ(data.size(), 12 + packet.payload.size());
    PASS();
}

TEST(BlazePacket_DecodeEmpty) {
    // Create a minimal packet
    Packet original;
    original.component = ComponentId::Util;
    original.command = static_cast<uint16_t>(UtilCommand::Ping);
    original.errorCode = 0;
    original.type = PacketType::Message;
    original.msgId = 100;
    
    auto encoded = BlazeCodec::encode(original);
    
    Packet decoded;
    size_t consumed = BlazeCodec::decode(encoded.data(), encoded.size(), decoded);
    
    ASSERT_TRUE(consumed > 0);
    ASSERT_TRUE(decoded.component == original.component);
    ASSERT_EQ(decoded.command, original.command);
    ASSERT_EQ(decoded.msgId, original.msgId);
    PASS();
}

TEST(BlazePacket_Roundtrip) {
    Packet original;
    original.component = ComponentId::GameManager;
    original.command = static_cast<uint16_t>(GameManagerCommand::CreateGame);
    original.errorCode = 0;
    original.type = PacketType::Message;
    original.msgId = 12345;
    
    TdfWriter writer;
    writer.writeString("NAME", "My Game Room");
    writer.writeInteger("MAXP", 8);
    writer.writeInteger("PRIV", 0);
    original.payload = writer.take();
    
    // Encode
    auto encoded = BlazeCodec::encode(original);
    
    // Decode
    Packet decoded;
    size_t consumed = BlazeCodec::decode(encoded.data(), encoded.size(), decoded);
    
    ASSERT_EQ(consumed, encoded.size());
    ASSERT_TRUE(decoded.component == original.component);
    ASSERT_EQ(decoded.command, original.command);
    ASSERT_EQ(decoded.msgId, original.msgId);
    ASSERT_EQ(decoded.payload.size(), original.payload.size());
    
    // Verify payload bytes match
    for (size_t i = 0; i < original.payload.size(); i++) {
        if (decoded.payload[i] != original.payload[i]) {
            _msg = "Payload mismatch at byte " + std::to_string(i);
            return false;
        }
    }
    PASS();
}

TEST(BlazePacket_Reply) {
    Packet request;
    request.component = ComponentId::Authentication;
    request.command = static_cast<uint16_t>(AuthCommand::Login);
    request.errorCode = 0;
    request.type = PacketType::Message;
    request.msgId = 999;
    
    Packet reply = BlazeCodec::createReply(request);
    
    ASSERT_TRUE(reply.component == request.component);
    ASSERT_EQ(reply.command, request.command);
    ASSERT_EQ(reply.msgId, request.msgId);
    ASSERT_TRUE(reply.type == PacketType::Reply);
    PASS();
}

TEST(BlazePacket_ErrorReply) {
    Packet request;
    request.component = ComponentId::GameManager;
    request.command = static_cast<uint16_t>(GameManagerCommand::JoinGame);
    request.msgId = 500;
    
    Packet error = BlazeCodec::createErrorReply(request, BlazeError::GameNotFound);
    
    ASSERT_TRUE(error.component == request.component);
    ASSERT_EQ(error.command, request.command);
    ASSERT_EQ(error.msgId, request.msgId);
    ASSERT_TRUE(error.type == PacketType::ErrorReply);
    ASSERT_EQ(error.errorCode, static_cast<uint16_t>(BlazeError::GameNotFound));
    PASS();
}

// =============================================================================
// Partial Packet Tests
// =============================================================================

TEST(BlazePacket_PartialHeader) {
    // Create a valid packet
    Packet packet;
    packet.component = ComponentId::Util;
    packet.command = static_cast<uint16_t>(UtilCommand::Ping);
    packet.msgId = 1;
    
    auto encoded = BlazeCodec::encode(packet);
    
    // Try to decode with only partial data
    Packet decoded;
    size_t consumed = BlazeCodec::decode(encoded.data(), 6, decoded);  // Only 6 bytes
    
    // Should return 0 (need more data)
    ASSERT_EQ(consumed, 0u);
    PASS();
}

TEST(BlazePacket_PartialPayload) {
    Packet packet;
    packet.component = ComponentId::Authentication;
    packet.command = static_cast<uint16_t>(AuthCommand::Login);
    packet.msgId = 1;
    
    TdfWriter writer;
    writer.writeString("DATA", "Some data here");
    packet.payload = writer.take();
    
    auto encoded = BlazeCodec::encode(packet);
    
    // Try to decode with incomplete payload
    Packet decoded;
    size_t consumed = BlazeCodec::decode(encoded.data(), 14, decoded);  // Header + 2 bytes
    
    // Should return 0 (need more data)
    ASSERT_EQ(consumed, 0u);
    PASS();
}

// =============================================================================
// Component ID Tests
// =============================================================================

TEST(ComponentId_Values) {
    // Verify component IDs match expected values
    ASSERT_EQ(static_cast<uint16_t>(ComponentId::Authentication), 0x01);
    ASSERT_EQ(static_cast<uint16_t>(ComponentId::GameManager), 0x04);
    ASSERT_EQ(static_cast<uint16_t>(ComponentId::Redirector), 0x05);
    ASSERT_EQ(static_cast<uint16_t>(ComponentId::Stats), 0x07);
    ASSERT_EQ(static_cast<uint16_t>(ComponentId::Util), 0x09);
    PASS();
}
