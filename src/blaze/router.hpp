#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>

#include "blaze/frame.hpp"
#include "blaze/tdf.hpp"
#include "core/byte_io.hpp"

namespace opends2::net {
class Session;
}

namespace opends2::blaze {

struct Reply {
    std::uint16_t error = 0;  // non-zero sends an ErrorResponse
    Bytes payload;
};

struct RequestContext {
    net::Session& session;
    const FrameHeader& header;
    const tdf::Group& body;
};

using Handler = std::function<Reply(RequestContext&)>;

struct Route {
    std::string name;
    Handler handler;
};

// Maps (component, command) pairs to request handlers.
class Router {
public:
    // Throws std::logic_error if the pair is already registered.
    void add(std::uint16_t component, std::uint16_t command, std::string name, Handler handler);

    // Returns nullptr if nothing is registered for the pair.
    const Route* find(std::uint16_t component, std::uint16_t command) const;

private:
    static constexpr std::uint32_t key(std::uint16_t component, std::uint16_t command) {
        return (static_cast<std::uint32_t>(component) << 16) | command;
    }

    std::unordered_map<std::uint32_t, Route> routes_;
};

}  // namespace opends2::blaze
