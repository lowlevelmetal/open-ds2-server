#include "network/client_connection.hpp"
#include "utils/logger.hpp"
#include <arpa/inet.h>

namespace ds2::network {

ClientConnection::ClientConnection(
    std::shared_ptr<asio::ssl::stream<tcp::socket>> socket,
    uint64_t connectionId
)
    : m_socket(socket)
    , m_connectionId(connectionId)
    , m_running(false)
    , m_writing(false)
{
    m_headerBuffer.resize(sizeof(blaze::PacketHeader));
}

ClientConnection::~ClientConnection() {
    stop();
}

void ClientConnection::start() {
    if (m_running) return;
    
    m_running = true;
    LOG_INFO("[Conn:{}] Started from {}", m_connectionId, getRemoteAddress());
    
    doReadHeader();
}

void ClientConnection::stop() {
    if (!m_running) return;
    
    m_running = false;
    
    asio::error_code ec;
    m_socket->lowest_layer().shutdown(tcp::socket::shutdown_both, ec);
    m_socket->lowest_layer().close(ec);
    
    LOG_INFO("[Conn:{}] Closed", m_connectionId);
    
    if (m_disconnectHandler) {
        // Call handler (but be careful about shared_ptr cycles)
        auto self = shared_from_this();
        m_disconnectHandler(self);
    }
}

void ClientConnection::sendPacket(const blaze::Packet& packet) {
    if (!m_running) return;
    
    std::vector<uint8_t> data = packet.serialize();
    
    LOG_DEBUG("[Conn:{}] Sending packet: component=0x{:04X} cmd=0x{:04X} len={}",
              m_connectionId,
              static_cast<uint16_t>(packet.getComponent()),
              packet.getCommand(),
              data.size());
    
    {
        std::lock_guard<std::mutex> lock(m_writeMutex);
        m_writeQueue.push(std::move(data));
    }
    
    // Start write if not already writing
    if (!m_writing) {
        doWrite();
    }
}

void ClientConnection::sendPacket(std::unique_ptr<blaze::Packet> packet) {
    if (packet) {
        sendPacket(*packet);
    }
}

void ClientConnection::setPacketHandler(PacketHandler handler) {
    m_packetHandler = handler;
}

void ClientConnection::setDisconnectHandler(DisconnectHandler handler) {
    m_disconnectHandler = handler;
}

std::string ClientConnection::getRemoteAddress() const {
    try {
        return m_socket->lowest_layer().remote_endpoint().address().to_string();
    }
    catch (...) {
        return "unknown";
    }
}

uint16_t ClientConnection::getRemotePort() const {
    try {
        return m_socket->lowest_layer().remote_endpoint().port();
    }
    catch (...) {
        return 0;
    }
}

void ClientConnection::doReadHeader() {
    if (!m_running) return;
    
    auto self = shared_from_this();
    
    asio::async_read(
        *m_socket,
        asio::buffer(m_headerBuffer),
        [this, self](const asio::error_code& error, size_t bytes_transferred) {
            handleReadHeader(error, bytes_transferred);
        }
    );
}

void ClientConnection::handleReadHeader(const asio::error_code& error, size_t bytes_transferred) {
    if (!m_running) return;
    
    if (error) {
        if (error != asio::error::eof && error != asio::error::operation_aborted) {
            LOG_ERROR("[Conn:{}] Read header error: {}", m_connectionId, error.message());
        }
        stop();
        return;
    }
    
    if (bytes_transferred != sizeof(blaze::PacketHeader)) {
        LOG_ERROR("[Conn:{}] Incomplete header", m_connectionId);
        stop();
        return;
    }
    
    // Parse header to get payload length
    const blaze::PacketHeader* header = 
        reinterpret_cast<const blaze::PacketHeader*>(m_headerBuffer.data());
    
    uint16_t payloadLen = ntohs(header->length);
    
    LOG_DEBUG("[Conn:{}] Header: component=0x{:04X} cmd=0x{:04X} len={}",
              m_connectionId,
              ntohs(header->component),
              ntohs(header->command),
              payloadLen);
    
    if (payloadLen > 0) {
        doReadPayload(payloadLen);
    }
    else {
        // No payload, process packet now
        auto packet = blaze::Packet::parse(m_headerBuffer);
        if (packet && m_packetHandler) {
            m_packetHandler(shared_from_this(), std::move(packet));
        }
        doReadHeader();
    }
}

void ClientConnection::doReadPayload(size_t length) {
    if (!m_running) return;
    
    m_payloadBuffer.resize(length);
    auto self = shared_from_this();
    
    asio::async_read(
        *m_socket,
        asio::buffer(m_payloadBuffer),
        [this, self](const asio::error_code& error, size_t bytes_transferred) {
            handleReadPayload(error, bytes_transferred);
        }
    );
}

void ClientConnection::handleReadPayload(const asio::error_code& error, size_t /*bytes_transferred*/) {
    if (!m_running) return;
    
    if (error) {
        LOG_ERROR("[Conn:{}] Read payload error: {}", m_connectionId, error.message());
        stop();
        return;
    }
    
    // Combine header + payload
    std::vector<uint8_t> fullPacket;
    fullPacket.reserve(m_headerBuffer.size() + m_payloadBuffer.size());
    fullPacket.insert(fullPacket.end(), m_headerBuffer.begin(), m_headerBuffer.end());
    fullPacket.insert(fullPacket.end(), m_payloadBuffer.begin(), m_payloadBuffer.end());
    
    // Parse and handle packet
    auto packet = blaze::Packet::parse(fullPacket);
    if (packet && m_packetHandler) {
        m_packetHandler(shared_from_this(), std::move(packet));
    }
    
    // Continue reading
    doReadHeader();
}

void ClientConnection::doWrite() {
    if (!m_running) return;
    
    std::lock_guard<std::mutex> lock(m_writeMutex);
    
    if (m_writeQueue.empty()) {
        m_writing = false;
        return;
    }
    
    m_writing = true;
    auto self = shared_from_this();
    
    // Get front of queue (don't pop yet)
    const auto& data = m_writeQueue.front();
    
    asio::async_write(
        *m_socket,
        asio::buffer(data),
        [this, self](const asio::error_code& error, size_t bytes_transferred) {
            handleWrite(error, bytes_transferred);
        }
    );
}

void ClientConnection::handleWrite(const asio::error_code& error, size_t /*bytes_transferred*/) {
    if (error) {
        LOG_ERROR("[Conn:{}] Write error: {}", m_connectionId, error.message());
        stop();
        return;
    }
    
    {
        std::lock_guard<std::mutex> lock(m_writeMutex);
        m_writeQueue.pop();
    }
    
    // Continue writing if more in queue
    doWrite();
}

} // namespace ds2::network
