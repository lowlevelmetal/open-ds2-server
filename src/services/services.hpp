#pragma once

#include "blaze/router.hpp"
#include "core/config.hpp"

// Each Blaze component gets its own translation unit with a register_* function.
// Handlers capture `config` by reference; it must outlive the router.
namespace opends2::services {

void register_redirector(blaze::Router& router, const Config& config);
void register_util(blaze::Router& router, const Config& config);

inline void register_all(blaze::Router& router, const Config& config) {
    register_redirector(router, config);
    register_util(router, config);
}

}  // namespace opends2::services
