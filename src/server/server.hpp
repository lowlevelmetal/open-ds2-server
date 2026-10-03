#pragma once

#include <cstdint>
#include <string>

#include <asio/awaitable.hpp>
#include <asio/io_context.hpp>
#include <asio/ip/tcp.hpp>

#include "blaze/router.hpp"
#include "core/config.hpp"
#include "net/session.hpp"

namespace opends2 {

// Owns the listeners and the request router.
//
// Two listeners are started: the redirector (the first thing the game contacts)
// and the main Blaze server it redirects to. Both share one router; which
// commands arrive where is up to the client.
class Server {
public:
    Server(asio::io_context& io, const Config& config);

    blaze::Router& router() { return router_; }

    // Binds the listeners. Throws std::system_error if a port is unavailable.
    void start();

private:
    asio::awaitable<void> accept_loop(asio::ip::tcp::acceptor acceptor, std::string name);
    void dispatch(net::Session& session, blaze::Frame frame);

    asio::io_context& io_;
    const Config& config_;
    blaze::Router router_;
    std::uint64_t next_session_id_ = 1;
};

}  // namespace opends2
