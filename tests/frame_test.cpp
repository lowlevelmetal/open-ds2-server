#include <gtest/gtest.h>

#include "blaze/frame.hpp"

using namespace opends2;
using namespace opends2::blaze;

TEST(Frame, EncodeThenReadRoundTrips) {
    FrameHeader header;
    header.component = 0x0005;
    header.command = 0x0001;
    header.type = MessageType::Response;
    header.msg_id = 42;
    const Bytes payload{std::byte{0xAA}, std::byte{0xBB}};

    const auto encoded = encode_frame(header, payload);
    ASSERT_EQ(encoded.size(), kHeaderSize + payload.size());
    EXPECT_EQ(encoded[1], std::byte{0x02});  // length low byte

    ByteReader in(encoded);
    const auto frame = read_frame(in);
    EXPECT_TRUE(in.empty());
    EXPECT_EQ(frame.header.length, 2u);
    EXPECT_EQ(frame.header.component, 0x0005);
    EXPECT_EQ(frame.header.command, 0x0001);
    EXPECT_EQ(frame.header.type, MessageType::Response);
    EXPECT_EQ(frame.header.msg_id, 42);
    EXPECT_FALSE(frame.header.has_extended_length());
    EXPECT_EQ(frame.payload, payload);
}

TEST(Frame, LargePayloadUsesExtendedLength) {
    const Bytes payload(0x12345, std::byte{0x01});
    const auto encoded = encode_frame(FrameHeader{}, payload);
    ASSERT_EQ(encoded.size(), kHeaderSize + kExtendedLengthSize + payload.size());

    ByteReader in(encoded);
    const auto frame = read_frame(in);
    EXPECT_TRUE(frame.header.has_extended_length());
    EXPECT_EQ(frame.header.length, 0x12345u);
    EXPECT_EQ(frame.payload.size(), payload.size());
}

TEST(Frame, TruncatedFrameThrows) {
    auto encoded = encode_frame(FrameHeader{}, Bytes(10, std::byte{0}));
    encoded.pop_back();
    ByteReader in(encoded);
    EXPECT_THROW(read_frame(in), DecodeError);
}
