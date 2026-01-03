#include "tcp_server.hpp"
#include "utils/logger.hpp"

#include <cstring>

namespace ds2 {
namespace network {

// Platform-specific initialization
static bool g_networkInitialized = false;

bool initializeNetworking() {
    if (g_networkInitialized) {
        return true;
    }
    
#ifdef _WIN32
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        LOG_ERROR("Failed to initialize Winsock");
        return false;
    }
#endif
    
    g_networkInitialized = true;
    return true;
}

void cleanupNetworking() {
    if (!g_networkInitialized) {
        return;
    }
    
#ifdef _WIN32
    WSACleanup();
#endif
    
    g_networkInitialized = false;
}

// =============================================================================
// TcpSocket Implementation
// =============================================================================

TcpSocket::TcpSocket() {
    initializeNetworking();
}

TcpSocket::TcpSocket(socket_t socket, const sockaddr_in& addr)
    : m_socket(socket)
    , m_remoteAddr(addr)
{
    initializeNetworking();
    setNonBlocking(true);
    setNoDelay(true);
}

TcpSocket::~TcpSocket() {
    close();
}

TcpSocket::TcpSocket(TcpSocket&& other) noexcept
    : m_socket(other.m_socket)
    , m_remoteAddr(other.m_remoteAddr)
{
    other.m_socket = INVALID_SOCKET_VALUE;
    std::memset(&other.m_remoteAddr, 0, sizeof(other.m_remoteAddr));
}

TcpSocket& TcpSocket::operator=(TcpSocket&& other) noexcept {
    if (this != &other) {
        close();
        m_socket = other.m_socket;
        m_remoteAddr = other.m_remoteAddr;
        other.m_socket = INVALID_SOCKET_VALUE;
        std::memset(&other.m_remoteAddr, 0, sizeof(other.m_remoteAddr));
    }
    return *this;
}

bool TcpSocket::connect(const std::string& host, uint16_t port) {
    if (m_socket != INVALID_SOCKET_VALUE) {
        close();
    }
    
    m_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_socket == INVALID_SOCKET_VALUE) {
        LOG_ERROR("Failed to create socket");
        return false;
    }
    
    // Resolve hostname
    struct addrinfo hints{}, *result = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &result) != 0) {
        LOG_ERROR("Failed to resolve host: " + host);
        close();
        return false;
    }
    
    // Try to connect
    bool connected = false;
    for (auto* ptr = result; ptr != nullptr; ptr = ptr->ai_next) {
        if (::connect(m_socket, ptr->ai_addr, ptr->ai_addrlen) == 0) {
            std::memcpy(&m_remoteAddr, ptr->ai_addr, sizeof(m_remoteAddr));
            connected = true;
            break;
        }
    }
    
    freeaddrinfo(result);
    
    if (!connected) {
        LOG_ERROR("Failed to connect to " + host + ":" + std::to_string(port));
        close();
        return false;
    }
    
    setNonBlocking(true);
    setNoDelay(true);
    
    return true;
}

int TcpSocket::send(const uint8_t* data, size_t length) {
    if (m_socket == INVALID_SOCKET_VALUE) {
        return -1;
    }
    
#ifdef _WIN32
    return ::send(m_socket, reinterpret_cast<const char*>(data), static_cast<int>(length), 0);
#else
    return ::send(m_socket, data, length, MSG_NOSIGNAL);
#endif
}

int TcpSocket::receive(uint8_t* buffer, size_t maxLength) {
    if (m_socket == INVALID_SOCKET_VALUE) {
        return -1;
    }
    
#ifdef _WIN32
    int result = ::recv(m_socket, reinterpret_cast<char*>(buffer), static_cast<int>(maxLength), 0);
    if (result == SOCKET_ERROR) {
        int err = WSAGetLastError();
        if (err == WSAEWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
    return result;
#else
    ssize_t result = ::recv(m_socket, buffer, maxLength, 0);
    if (result < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return 0;
        }
        return -1;
    }
    return static_cast<int>(result);
#endif
}

void TcpSocket::close() {
    if (m_socket != INVALID_SOCKET_VALUE) {
#ifdef _WIN32
        ::closesocket(m_socket);
#else
        ::close(m_socket);
#endif
        m_socket = INVALID_SOCKET_VALUE;
    }
}

bool TcpSocket::setNonBlocking(bool nonBlocking) {
    if (m_socket == INVALID_SOCKET_VALUE) {
        return false;
    }
    
#ifdef _WIN32
    u_long mode = nonBlocking ? 1 : 0;
    return ioctlsocket(m_socket, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(m_socket, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    
    if (nonBlocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    
    return fcntl(m_socket, F_SETFL, flags) == 0;
#endif
}

bool TcpSocket::setNoDelay(bool noDelay) {
    if (m_socket == INVALID_SOCKET_VALUE) {
        return false;
    }
    
    int flag = noDelay ? 1 : 0;
    return setsockopt(m_socket, IPPROTO_TCP, TCP_NODELAY, 
                      reinterpret_cast<const char*>(&flag), sizeof(flag)) == 0;
}

std::string TcpSocket::getRemoteAddress() const {
    char addr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &m_remoteAddr.sin_addr, addr, INET_ADDRSTRLEN);
    return std::string(addr) + ":" + std::to_string(ntohs(m_remoteAddr.sin_port));
}

uint16_t TcpSocket::getRemotePort() const {
    return ntohs(m_remoteAddr.sin_port);
}

// =============================================================================
// TcpServer Implementation
// =============================================================================

TcpServer::TcpServer() {
    initializeNetworking();
}

TcpServer::~TcpServer() {
    close();
}

bool TcpServer::bind(const std::string& address, uint16_t port) {
    if (m_socket != INVALID_SOCKET_VALUE) {
        close();
    }
    
    m_socket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_socket == INVALID_SOCKET_VALUE) {
        LOG_ERROR("Failed to create server socket");
        return false;
    }
    
    // Allow address reuse
    int opt = 1;
    setsockopt(m_socket, SOL_SOCKET, SO_REUSEADDR, 
               reinterpret_cast<const char*>(&opt), sizeof(opt));
    
    // Setup address
    m_addr.sin_family = AF_INET;
    m_addr.sin_port = htons(port);
    
    if (address == "0.0.0.0" || address.empty()) {
        m_addr.sin_addr.s_addr = INADDR_ANY;
    } else {
        inet_pton(AF_INET, address.c_str(), &m_addr.sin_addr);
    }
    
    // Bind
    if (::bind(m_socket, reinterpret_cast<sockaddr*>(&m_addr), sizeof(m_addr)) < 0) {
        LOG_ERROR("Failed to bind to " + address + ":" + std::to_string(port));
        close();
        return false;
    }
    
    return true;
}

bool TcpServer::listen(int backlog) {
    if (m_socket == INVALID_SOCKET_VALUE) {
        LOG_ERROR("Cannot listen: socket not bound");
        return false;
    }
    
    if (::listen(m_socket, backlog) < 0) {
        LOG_ERROR("Failed to listen on socket");
        return false;
    }
    
    return true;
}

std::unique_ptr<TcpSocket> TcpServer::accept() {
    if (m_socket == INVALID_SOCKET_VALUE) {
        return nullptr;
    }
    
    sockaddr_in clientAddr{};
    socklen_t addrLen = sizeof(clientAddr);
    
    socket_t clientSocket = ::accept(m_socket, 
                                     reinterpret_cast<sockaddr*>(&clientAddr), 
                                     &addrLen);
    
    if (clientSocket == INVALID_SOCKET_VALUE) {
        return nullptr;
    }
    
    return std::make_unique<TcpSocket>(clientSocket, clientAddr);
}

void TcpServer::close() {
    if (m_socket != INVALID_SOCKET_VALUE) {
#ifdef _WIN32
        ::closesocket(m_socket);
#else
        ::close(m_socket);
#endif
        m_socket = INVALID_SOCKET_VALUE;
    }
}

} // namespace network
} // namespace ds2
