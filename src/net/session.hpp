#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <string>

#include <asio/awaitable.hpp>
#include <asio/ip/tcp.hpp>
#include <asio/steady_timer.hpp>

#include "blaze/frame.hpp"

namespace opends2::net {

// One client connection. Reads Blaze frames and hands them to a FrameHandler;
// outgoing frames are queued and written in order by a dedicated coroutine.
//
// Sessions run on a single-threaded io_context, so no locking is needed.
class Session : public std::enable_shared_from_this<Session> {
public:
    using FrameHandler = std::function<void(Session&, blaze::Frame)>;

    Session(asio::ip::tcp::socket socket, std::uint64_t id, std::string listener, FrameHandler handler);

    void start();
    void close();

    // Replies to a request, echoing its component/command/msg_id.
    void reply(const blaze::FrameHeader& request, std::uint16_t error, ByteView payload);

    // Sends an unsolicited notification.
    void notify(std::uint16_t component, std::uint16_t command, ByteView payload);

    std::uint64_t id() const { return id_; }
    const std::string& peer() const { return peer_; }
    const std::string& listener() const { return listener_; }

private:
    asio::awaitable<void> read_loop();
    asio::awaitable<void> write_loop();
    void send(const blaze::FrameHeader& header, ByteView payload);

    asio::ip::tcp::socket socket_;
    asio::steady_timer write_signal_;
    std::deque<Bytes> write_queue_;
    std::uint64_t id_;
    std::string listener_;
    std::string peer_;
    FrameHandler handler_;
};

}  // namespace opends2::net
