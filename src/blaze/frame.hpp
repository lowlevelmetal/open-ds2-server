#pragma once

// Blaze packet framing (Blaze 3 layout, unverified for Dead Space 2):
//
//   u16 length      payload length (low 16 bits)
//   u16 component
//   u16 command
//   u16 error
//   u8  type        MessageType
//   u8  options     0x10 = jumbo frame: a u16 with the high length bits follows
//   u16 msg_id      echoed in the response
//  [u16 length_hi]  only when (options & kOptionJumbo)
//   ... payload (TDF)
//
// All integers are big-endian.

#include <cstddef>
#include <cstdint>
#include <span>

#include "core/byte_io.hpp"

namespace opends2::blaze {

enum class MessageType : std::uint8_t {
    Request = 0x00,
    Response = 0x10,
    Notification = 0x20,
    ErrorResponse = 0x30,
};

inline constexpr std::size_t kHeaderSize = 12;
inline constexpr std::size_t kExtendedLengthSize = 2;
inline constexpr std::uint8_t kOptionJumbo = 0x10;

struct FrameHeader {
    std::uint32_t length = 0;
    std::uint16_t component = 0;
    std::uint16_t command = 0;
    std::uint16_t error = 0;
    MessageType type = MessageType::Request;
    std::uint8_t options = 0;
    std::uint16_t msg_id = 0;

    bool has_extended_length() const { return (options & kOptionJumbo) != 0; }
};

struct Frame {
    FrameHeader header;
    Bytes payload;
};

// Parses the fixed-size header. When has_extended_length() is true, read two more
// bytes and pass them to apply_extended_length() before reading the payload.
FrameHeader parse_header(std::span<const std::byte, kHeaderSize> data);
void apply_extended_length(FrameHeader& header, std::span<const std::byte, kExtendedLengthSize> data);

// Reads one complete frame from a contiguous buffer. Throws DecodeError if truncated.
Frame read_frame(ByteReader& in);

// Serializes a frame. header.length and the jumbo option are derived from the payload.
Bytes encode_frame(FrameHeader header, ByteView payload);

}  // namespace opends2::blaze
