#include "blaze/frame.hpp"

#include <limits>

namespace opends2::blaze {

FrameHeader parse_header(std::span<const std::byte, kHeaderSize> data) {
    ByteReader in(data);
    FrameHeader h;
    h.length = in.u16();
    h.component = in.u16();
    h.command = in.u16();
    h.error = in.u16();
    h.type = static_cast<MessageType>(in.u8());
    h.options = in.u8();
    h.msg_id = in.u16();
    return h;
}

void apply_extended_length(FrameHeader& header, std::span<const std::byte, kExtendedLengthSize> data) {
    ByteReader in(data);
    header.length |= static_cast<std::uint32_t>(in.u16()) << 16;
}

Frame read_frame(ByteReader& in) {
    const auto head = in.bytes(kHeaderSize);
    Frame frame{parse_header(head.first<kHeaderSize>()), {}};
    if (frame.header.has_extended_length()) {
        apply_extended_length(frame.header, in.bytes(kExtendedLengthSize).first<kExtendedLengthSize>());
    }
    const auto payload = in.bytes(frame.header.length);
    frame.payload.assign(payload.begin(), payload.end());
    return frame;
}

Bytes encode_frame(FrameHeader header, ByteView payload) {
    if (payload.size() > std::numeric_limits<std::uint32_t>::max()) {
        throw std::length_error("Blaze payload too large");
    }
    header.length = static_cast<std::uint32_t>(payload.size());
    const bool jumbo = header.length > 0xFFFF;
    header.options = static_cast<std::uint8_t>(jumbo ? (header.options | kOptionJumbo)
                                                     : (header.options & ~kOptionJumbo));

    ByteWriter out;
    out.u16(static_cast<std::uint16_t>(header.length));
    out.u16(header.component);
    out.u16(header.command);
    out.u16(header.error);
    out.u8(static_cast<std::uint8_t>(header.type));
    out.u8(header.options);
    out.u16(header.msg_id);
    if (jumbo) out.u16(static_cast<std::uint16_t>(header.length >> 16));
    out.bytes(payload);
    return out.take();
}

}  // namespace opends2::blaze
