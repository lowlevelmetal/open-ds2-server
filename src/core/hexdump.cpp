#include "core/hexdump.hpp"

#include <algorithm>
#include <format>
#include <iterator>

namespace opends2 {

std::string hexdump(ByteView data, std::size_t max_bytes) {
    constexpr std::size_t kWidth = 16;
    const std::size_t shown = std::min(data.size(), max_bytes);

    std::string out;
    for (std::size_t offset = 0; offset < shown; offset += kWidth) {
        const std::size_t count = std::min(kWidth, shown - offset);
        std::format_to(std::back_inserter(out), "{:08x}  ", offset);

        for (std::size_t i = 0; i < kWidth; ++i) {
            if (i < count) {
                std::format_to(std::back_inserter(out), "{:02x} ", std::to_integer<unsigned>(data[offset + i]));
            } else {
                out += "   ";
            }
            if (i == 7) out += ' ';
        }

        out += " |";
        for (std::size_t i = 0; i < count; ++i) {
            const auto c = std::to_integer<unsigned char>(data[offset + i]);
            out += (c >= 0x20 && c < 0x7F) ? static_cast<char>(c) : '.';
        }
        out += "|\n";
    }

    if (shown < data.size()) {
        std::format_to(std::back_inserter(out), "... ({} more bytes)\n", data.size() - shown);
    }
    return out;
}

}  // namespace opends2
