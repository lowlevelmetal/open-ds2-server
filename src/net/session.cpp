#include "net/session.hpp"

#include <array>
#include <format>

#include <asio/co_spawn.hpp>
#include <asio/detached.hpp>
#include <asio/read.hpp>
#include <asio/redirect_error.hpp>
#include <asio/use_awaitable.hpp>
#include <asio/write.hpp>

#include "blaze/components.hpp"
#include "core/hexdump.hpp"
#include "core/log.hpp"

namespace opends2::net {

namespace {

// Upper bound on a single frame's payload; larger frames drop the connection.
constexpr std::uint32_t kMaxPayload = 4 * 1024 * 1024;

std::string describe_peer(const asio::ip::tcp::socket& socket) {
    asio::error_code ec;
    const auto ep = socket.remote_endpoint(ec);
    return ec ? std::string("?") : std::format("{}:{}", ep.address().to_string(), ep.port());
}

}  // namespace

Session::Session(asio::ip::tcp::socket socket, std::uint64_t id, std::string listener, FrameHandler handler)
    : socket_(std::move(socket)),
      write_signal_(socket_.get_executor()),
      id_(id),
      listener_(std::move(listener)),
      peer_(describe_peer(socket_)),
      handler_(std::move(handler)) {
    write_signal_.expires_at(asio::steady_timer::time_point::max());
}

void Session::start() {
    log::info("[{}#{}] connection from {}", listener_, id_, peer_);
    asio::co_spawn(socket_.get_executor(), [self = shared_from_this()] { return self->read_loop(); }, asio::detached);
    asio::co_spawn(socket_.get_executor(), [self = shared_from_this()] { return self->write_loop(); }, asio::detached);
}

void Session::close() {
    if (!socket_.is_open()) return;
    log::info("[{}#{}] closed", listener_, id_);
    asio::error_code ignored;
    socket_.shutdown(asio::ip::tcp::socket::shutdown_both, ignored);
    socket_.close(ignored);
    write_signal_.cancel();
}

void Session::reply(const blaze::FrameHeader& request, std::uint16_t error, ByteView payload) {
    blaze::FrameHeader header;
    header.component = request.component;
    header.command = request.command;
    header.error = error;
    header.type = error == 0 ? blaze::MessageType::Response : blaze::MessageType::ErrorResponse;
    header.msg_id = request.msg_id;
    send(header, payload);
}

void Session::notify(std::uint16_t component, std::uint16_t command, ByteView payload) {
    blaze::FrameHeader header;
    header.component = component;
    header.command = command;
    header.type = blaze::MessageType::Notification;
    send(header, payload);
}

void Session::send(const blaze::FrameHeader& header, ByteView payload) {
    if (!socket_.is_open()) return;
    log::debug("[{}#{}] -> {}::0x{:04x} type=0x{:02x} id={} len={}", listener_, id_,
               blaze::component_name(header.component), header.command, static_cast<unsigned>(header.type),
               header.msg_id, payload.size());
    log::trace("[{}#{}] payload:\n{}", listener_, id_, hexdump(payload));

    write_queue_.push_back(blaze::encode_frame(header, payload));
    write_signal_.cancel_one();
}

asio::awaitable<void> Session::read_loop() {
    try {
        std::array<std::byte, blaze::kHeaderSize> head{};
        std::array<std::byte, blaze::kExtendedLengthSize> ext{};
        for (;;) {
            co_await asio::async_read(socket_, asio::buffer(head), asio::use_awaitable);
            auto header = blaze::parse_header(head);
            if (header.has_extended_length()) {
                co_await asio::async_read(socket_, asio::buffer(ext), asio::use_awaitable);
                blaze::apply_extended_length(header, ext);
            }
            if (header.length > kMaxPayload) {
                log::warn("[{}#{}] frame too large ({} bytes), dropping connection", listener_, id_, header.length);
                break;
            }

            Bytes payload(header.length);
            co_await asio::async_read(socket_, asio::buffer(payload), asio::use_awaitable);
            handler_(*this, blaze::Frame{header, std::move(payload)});
        }
    } catch (const std::system_error& e) {
        if (e.code() == asio::error::eof || e.code() == asio::error::connection_reset ||
            e.code() == asio::error::operation_aborted) {
            log::debug("[{}#{}] peer disconnected", listener_, id_);
        } else {
            log::warn("[{}#{}] read error: {}", listener_, id_, e.what());
        }
    } catch (const std::exception& e) {
        log::error("[{}#{}] {}", listener_, id_, e.what());
    }
    close();
}

asio::awaitable<void> Session::write_loop() {
    try {
        while (socket_.is_open()) {
            if (write_queue_.empty()) {
                // Woken by send() or close() cancelling the timer.
                asio::error_code ec;
                co_await write_signal_.async_wait(asio::redirect_error(asio::use_awaitable, ec));
            } else {
                co_await asio::async_write(socket_, asio::buffer(write_queue_.front()), asio::use_awaitable);
                write_queue_.pop_front();
            }
        }
    } catch (const std::exception& e) {
        log::warn("[{}#{}] write error: {}", listener_, id_, e.what());
        close();
    }
}

}  // namespace opends2::net
