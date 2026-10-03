// tdfdump: decode Blaze frames or raw TDF payloads from hex.
//
// Paste bytes from Wireshark ("Copy > ...as a Hex Stream") or any hex dump
// without offsets. Whitespace, ':' and '0x' prefixes are ignored.
//
//   tdfdump < packet.hex          # input is one or more Blaze frames
//   tdfdump --raw < payload.hex   # input is a bare TDF payload

#include <cstdio>
#include <exception>
#include <format>
#include <iostream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>

#include "blaze/components.hpp"
#include "blaze/frame.hpp"
#include "blaze/tdf.hpp"
#include "core/hexdump.hpp"

using namespace opends2;

namespace {

std::optional<unsigned> hex_digit(char c) {
    if (c >= '0' && c <= '9') return static_cast<unsigned>(c - '0');
    if (c >= 'a' && c <= 'f') return static_cast<unsigned>(c - 'a' + 10);
    if (c >= 'A' && c <= 'F') return static_cast<unsigned>(c - 'A' + 10);
    return std::nullopt;
}

Bytes parse_hex(std::string_view text) {
    Bytes out;
    std::optional<unsigned> high;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (c == '0' && i + 1 < text.size() && (text[i + 1] == 'x' || text[i + 1] == 'X') && !high) {
            ++i;
            continue;
        }
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == ':') continue;

        const auto digit = hex_digit(c);
        if (!digit) throw std::invalid_argument(std::string("invalid hex character '") + c + "'");
        if (high) {
            out.push_back(static_cast<std::byte>((*high << 4) | *digit));
            high.reset();
        } else {
            high = digit;
        }
    }
    if (high) throw std::invalid_argument("odd number of hex digits");
    return out;
}

void print_payload(ByteView payload) {
    try {
        std::cout << tdf::dump(tdf::decode(payload));
    } catch (const DecodeError& e) {
        std::cout << "!! TDF decode failed: " << e.what() << "\n" << hexdump(payload);
    }
}

}  // namespace

int main(int argc, char** argv) {
    bool raw = false;
    for (int i = 1; i < argc; ++i) {
        const std::string_view arg = argv[i];
        if (arg == "--raw") {
            raw = true;
        } else {
            std::fputs("usage: tdfdump [--raw] < hex.txt\n", stderr);
            return arg == "--help" || arg == "-h" ? 0 : 2;
        }
    }

    try {
        const std::string text(std::istreambuf_iterator<char>(std::cin), {});
        const Bytes data = parse_hex(text);

        if (raw) {
            print_payload(data);
            return 0;
        }

        ByteReader in(data);
        while (!in.empty()) {
            const auto frame = blaze::read_frame(in);
            const auto& h = frame.header;
            std::cout << std::format("=== {} (0x{:04x}) cmd=0x{:04x} type=0x{:02x} err=0x{:04x} id={} len={}\n",
                                     blaze::component_name(h.component), h.component, h.command,
                                     static_cast<unsigned>(h.type), h.error, h.msg_id, h.length);
            print_payload(frame.payload);
        }
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << '\n';
        return 1;
    }
    return 0;
}
