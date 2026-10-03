#include "blaze/router.hpp"

#include <format>
#include <stdexcept>

namespace opends2::blaze {

void Router::add(std::uint16_t component, std::uint16_t command, std::string name, Handler handler) {
    const auto [it, inserted] = routes_.try_emplace(key(component, command), Route{std::move(name), std::move(handler)});
    if (!inserted) {
        throw std::logic_error(
            std::format("handler for 0x{:04x}:0x{:04x} already registered as '{}'", component, command, it->second.name));
    }
}

const Route* Router::find(std::uint16_t component, std::uint16_t command) const {
    const auto it = routes_.find(key(component, command));
    return it == routes_.end() ? nullptr : &it->second;
}

}  // namespace opends2::blaze
