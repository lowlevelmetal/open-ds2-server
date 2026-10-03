#include <asio/ip/address_v4.hpp>

#include "blaze/components.hpp"
#include "services/services.hpp"

namespace opends2::services {

namespace {

// The IP field is the IPv4 address as a big-endian integer; 0 if public_host is a name.
std::int64_t ipv4_as_int(const std::string& host) {
    asio::error_code ec;
    const auto address = asio::ip::make_address_v4(host, ec);
    return ec ? 0 : static_cast<std::int64_t>(address.to_uint());
}

}  // namespace

void register_redirector(blaze::Router& router, const Config& config) {
    // getServerInstance: the first request the game makes. Tells it where the
    // main Blaze server lives. Layout is from ME3-era Blaze 3; unverified for DS2.
    router.add(blaze::component::Redirector, blaze::redirector::GetServerInstance, "getServerInstance",
               [&config](blaze::RequestContext&) {
                   tdf::Writer w;
                   w.begin_union("ADDR", 0x00)
                       .begin_group("VALU")
                       .string("HOST", config.public_host)
                       .integer("IP", ipv4_as_int(config.public_host))
                       .integer("PORT", config.blaze_port)
                       .end_group();
                   w.boolean("SECU", false);  // main server connection without SSL
                   w.boolean("XDNS", false);
                   return blaze::Reply{.payload = w.take()};
               });
}

}  // namespace opends2::services
