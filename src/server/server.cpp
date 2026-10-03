#include "server/server.hpp"

#include <memory>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/use_awaitable.hpp>

#include "blaze/components.hpp"
#include "core/hexdump.hpp"
#include "core/log.hpp"

namespace opends2 {

namespace {

asio::ip::tcp::acceptor make_acceptor(asio::io_context& io, const std::string& address, std::uint16_t port) {
    const asio::ip::tcp::endpoint endpoint(asio::ip::make_address(address), port);
    asio::ip::tcp::acceptor acceptor(io);
    acceptor.open(endpoint.protocol());
    acceptor.set_option(asio::socket_base::reuse_address(true));
    acceptor.bind(endpoint);
    acceptor.listen();
    return acceptor;
}

}  // namespace

Server::Server(asio::io_context& io, const Config& config) : io_(io), config_(config) {}

void Server::start() {
    auto redirector = make_acceptor(io_, config_.bind_address, config_.redirector_port);
    auto blaze = make_acceptor(io_, config_.bind_address, config_.blaze_port);

    log::info("redirector listening on {}:{}", config_.bind_address, config_.redirector_port);
    log::info("blaze server listening on {}:{} (advertised as {})", config_.bind_address, config_.blaze_port,
              config_.public_host);

    asio::co_spawn(io_, accept_loop(std::move(redirector), "redirector"), asio::detached);
    asio::co_spawn(io_, accept_loop(std::move(blaze), "blaze"), asio::detached);
}

asio::awaitable<void> Server::accept_loop(asio::ip::tcp::acceptor acceptor, std::string name) {
    for (;;) {
        try {
            auto socket = co_await acceptor.async_accept(asio::use_awaitable);
            auto session = std::make_shared<net::Session>(
                std::move(socket), next_session_id_++, name,
                [this](net::Session& s, blaze::Frame frame) { dispatch(s, std::move(frame)); });
            session->start();
        } catch (const std::system_error& e) {
            if (e.code() == asio::error::operation_aborted) co_return;
            log::warn("[{}] accept failed: {}", name, e.what());
        }
    }
}

void Server::dispatch(net::Session& session, blaze::Frame frame) {
    const auto& h = frame.header;
    const auto* route = router_.find(h.component, h.command);
    log::debug("[{}#{}] <- {}::{} (0x{:04x}:0x{:04x}) type=0x{:02x} id={} len={}", session.listener(), session.id(),
               blaze::component_name(h.component), route ? route->name : "?", h.component, h.command,
               static_cast<unsigned>(h.type), h.msg_id, frame.payload.size());

    if (h.type != blaze::MessageType::Request) {
        log::warn("[{}#{}] ignoring non-request frame", session.listener(), session.id());
        return;
    }

    tdf::Group body;
    try {
        body = tdf::decode(frame.payload);
    } catch (const DecodeError& e) {
        // Most likely our understanding of DS2's TDF differs from Blaze 3. Keep the
        // connection up and log everything so the bytes can be studied.
        log::warn("[{}#{}] TDF decode failed: {}\n{}", session.listener(), session.id(), e.what(),
                  hexdump(frame.payload));
    }
    if (!body.fields.empty()) {
        log::trace("[{}#{}] request body:\n{}", session.listener(), session.id(), tdf::dump(body));
    }

    if (!route) {
        // TODO: confirm how the DS2 client reacts to an empty reply vs. an error.
        log::warn("[{}#{}] unhandled {}::0x{:04x} (component 0x{:04x})\n{}", session.listener(), session.id(),
                  blaze::component_name(h.component), h.command, h.component, tdf::dump(body));
        session.reply(h, 0, {});
        return;
    }

    blaze::RequestContext ctx{session, h, body};
    try {
        const auto reply = route->handler(ctx);
        session.reply(h, reply.error, reply.payload);
    } catch (const std::exception& e) {
        log::error("[{}#{}] handler '{}' threw: {}", session.listener(), session.id(), route->name, e.what());
        session.reply(h, 0, {});
    }
}

}  // namespace opends2
