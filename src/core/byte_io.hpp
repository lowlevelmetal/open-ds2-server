#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <utility>
#include <vector>

namespace opends2 {

using Bytes = std::vector<std::byte>;
using ByteView = std::span<const std::byte>;

// Thrown when incoming data is truncated or malformed.
struct DecodeError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Big-endian read cursor over a byte buffer. Throws DecodeError on underrun.
class ByteReader {
public:
    explicit ByteReader(ByteView data) : data_(data) {}

    std::uint8_t u8() {
        require(1);
        return std::to_integer<std::uint8_t>(data_[pos_++]);
    }

    std::uint16_t u16() {
        const auto hi = u8();
        const auto lo = u8();
        return static_cast<std::uint16_t>((hi << 8) | lo);
    }

    std::uint32_t u32() {
        const std::uint32_t hi = u16();
        const std::uint32_t lo = u16();
        return (hi << 16) | lo;
    }

    ByteView bytes(std::size_t n) {
        require(n);
        auto view = data_.subspan(pos_, n);
        pos_ += n;
        return view;
    }

    std::uint8_t peek_u8() const {
        require(1);
        return std::to_integer<std::uint8_t>(data_[pos_]);
    }

    std::size_t remaining() const { return data_.size() - pos_; }
    std::size_t position() const { return pos_; }
    bool empty() const { return remaining() == 0; }

private:
    void require(std::size_t n) const {
        if (remaining() < n) {
            throw DecodeError("unexpected end of data");
        }
    }

    ByteView data_;
    std::size_t pos_ = 0;
};

// Big-endian append-only byte buffer.
class ByteWriter {
public:
    void u8(std::uint8_t v) { buf_.push_back(std::byte{v}); }

    void u16(std::uint16_t v) {
        u8(static_cast<std::uint8_t>(v >> 8));
        u8(static_cast<std::uint8_t>(v));
    }

    void u32(std::uint32_t v) {
        u16(static_cast<std::uint16_t>(v >> 16));
        u16(static_cast<std::uint16_t>(v));
    }

    void bytes(ByteView v) { buf_.insert(buf_.end(), v.begin(), v.end()); }

    std::size_t size() const { return buf_.size(); }
    Bytes take() { return std::exchange(buf_, {}); }

private:
    Bytes buf_;
};

}  // namespace opends2
