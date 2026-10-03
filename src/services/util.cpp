#include <chrono>

#include "blaze/components.hpp"
#include "services/services.hpp"

namespace opends2::services {

void register_util(blaze::Router& router, const Config& /*config*/) {
    // ping: keep-alive; replies with the server time in Unix seconds.
    router.add(blaze::component::Util, blaze::util::Ping, "ping", [](blaze::RequestContext&) {
        const auto now = std::chrono::system_clock::now().time_since_epoch();
        tdf::Writer w;
        w.integer("STIM", std::chrono::duration_cast<std::chrono::seconds>(now).count());
        return blaze::Reply{.payload = w.take()};
    });

    // TODO: preAuth / postAuth / fetchClientConfig once their DS2 layouts are known.
}

}  // namespace opends2::services
