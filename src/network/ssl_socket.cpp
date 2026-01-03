#include "ssl_socket.hpp"
#include "utils/logger.hpp"

#include <cstring>
#include <netinet/tcp.h>

namespace ds2 {
namespace network {

// Global SSL initialization flag
static bool g_sslInitialized = false;

void initializeOpenSSL() {
    if (g_sslInitialized) {
        return;
    }
    
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    
    g_sslInitialized = true;
    LOG_INFO("OpenSSL initialized");
}

void cleanupOpenSSL() {
    if (!g_sslInitialized) {
        return;
    }
    
    EVP_cleanup();
    ERR_free_strings();
    
    g_sslInitialized = false;
}

// =============================================================================
// SslContext Implementation
// =============================================================================

SslContext::SslContext() {
    initializeOpenSSL();
}

SslContext::~SslContext() {
    if (m_ctx) {
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
    }
}

bool SslContext::initialize(const std::string& certFile, const std::string& keyFile) {
    // Create SSL context using TLS server method
    // Use TLS_server_method() for modern OpenSSL, supports TLS 1.0-1.3
    m_ctx = SSL_CTX_new(TLS_server_method());
    if (!m_ctx) {
        LOG_ERROR("Failed to create SSL context: " + getLastError());
        return false;
    }
    
    // Set minimum protocol version to TLS 1.0 for compatibility with older games
    // Dead Space 2 uses OpenSSL 1.0.0b which supports TLS 1.0
    SSL_CTX_set_min_proto_version(m_ctx, TLS1_VERSION);
    
    // Load certificate file
    if (SSL_CTX_use_certificate_file(m_ctx, certFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        LOG_ERROR("Failed to load certificate file '" + certFile + "': " + getLastError());
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return false;
    }
    
    // Load private key file
    if (SSL_CTX_use_PrivateKey_file(m_ctx, keyFile.c_str(), SSL_FILETYPE_PEM) <= 0) {
        LOG_ERROR("Failed to load private key file '" + keyFile + "': " + getLastError());
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return false;
    }
    
    // Verify private key matches certificate
    if (!SSL_CTX_check_private_key(m_ctx)) {
        LOG_ERROR("Private key does not match certificate: " + getLastError());
        SSL_CTX_free(m_ctx);
        m_ctx = nullptr;
        return false;
    }
    
    LOG_INFO("SSL context initialized with certificate: " + certFile);
    return true;
}

std::string SslContext::getLastError() {
    unsigned long err = ERR_get_error();
    if (err == 0) {
        return "No error";
    }
    
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    return std::string(buf);
}

// =============================================================================
// SslSocket Implementation
// =============================================================================

SslSocket::SslSocket() {
    initializeNetworking();
    initializeOpenSSL();
}

SslSocket::~SslSocket() {
    close();
}

SslSocket::SslSocket(SslSocket&& other) noexcept
    : m_ssl(other.m_ssl)
    , m_socket(other.m_socket)
    , m_remoteAddr(other.m_remoteAddr)
{
    other.m_ssl = nullptr;
    other.m_socket = INVALID_SOCKET_VALUE;
    std::memset(&other.m_remoteAddr, 0, sizeof(other.m_remoteAddr));
}

SslSocket& SslSocket::operator=(SslSocket&& other) noexcept {
    if (this != &other) {
        close();
        m_ssl = other.m_ssl;
        m_socket = other.m_socket;
        m_remoteAddr = other.m_remoteAddr;
        other.m_ssl = nullptr;
        other.m_socket = INVALID_SOCKET_VALUE;
        std::memset(&other.m_remoteAddr, 0, sizeof(other.m_remoteAddr));
    }
    return *this;
}

bool SslSocket::accept(socket_t socket, SslContext& ctx) {
    if (!ctx.isValid()) {
        LOG_ERROR("Cannot accept SSL connection: invalid context");
        return false;
    }
    
    m_socket = socket;
    
    // Get peer address
    socklen_t addrLen = sizeof(m_remoteAddr);
    if (getpeername(socket, (sockaddr*)&m_remoteAddr, &addrLen) < 0) {
        std::memset(&m_remoteAddr, 0, sizeof(m_remoteAddr));
    }
    
    // Create SSL structure
    m_ssl = SSL_new(ctx.get());
    if (!m_ssl) {
        LOG_ERROR("Failed to create SSL structure: " + SslContext::getLastError());
        return false;
    }
    
    // Associate socket with SSL
    if (!SSL_set_fd(m_ssl, static_cast<int>(socket))) {
        LOG_ERROR("Failed to set SSL file descriptor: " + SslContext::getLastError());
        SSL_free(m_ssl);
        m_ssl = nullptr;
        return false;
    }
    
    // Perform SSL handshake
    int ret = SSL_accept(m_ssl);
    if (ret <= 0) {
        int err = SSL_get_error(m_ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            // Non-blocking, would block - this is okay for async handling
            // For simplicity, we'll retry in blocking mode
        }
        
        // For now, log the error and fail
        LOG_ERROR("SSL handshake failed: " + SslContext::getLastError() + 
                  " (SSL error: " + std::to_string(err) + ")");
        SSL_free(m_ssl);
        m_ssl = nullptr;
        return false;
    }
    
    // Set socket to non-blocking after handshake
    setNonBlocking(true);
    
    LOG_DEBUG("SSL handshake completed with " + getRemoteAddress() + ":" + 
              std::to_string(getRemotePort()));
    return true;
}

int SslSocket::send(const uint8_t* data, size_t length) {
    if (!m_ssl) {
        return -1;
    }
    
    int ret = SSL_write(m_ssl, data, static_cast<int>(length));
    if (ret <= 0) {
        int err = SSL_get_error(m_ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 0;  // Would block
        }
        return -1;  // Error
    }
    
    return ret;
}

int SslSocket::receive(uint8_t* buffer, size_t maxLength) {
    if (!m_ssl) {
        return -1;
    }
    
    int ret = SSL_read(m_ssl, buffer, static_cast<int>(maxLength));
    if (ret <= 0) {
        int err = SSL_get_error(m_ssl, ret);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
            return 0;  // Would block, no data available
        }
        if (err == SSL_ERROR_ZERO_RETURN) {
            return -1;  // Connection closed cleanly
        }
        return -1;  // Error
    }
    
    return ret;
}

void SslSocket::close() {
    if (m_ssl) {
        SSL_shutdown(m_ssl);
        SSL_free(m_ssl);
        m_ssl = nullptr;
    }
    
    if (m_socket != INVALID_SOCKET_VALUE) {
#ifdef _WIN32
        closesocket(m_socket);
#else
        ::close(m_socket);
#endif
        m_socket = INVALID_SOCKET_VALUE;
    }
}

std::string SslSocket::getRemoteAddress() const {
    char addrStr[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &m_remoteAddr.sin_addr, addrStr, sizeof(addrStr));
    return std::string(addrStr);
}

uint16_t SslSocket::getRemotePort() const {
    return ntohs(m_remoteAddr.sin_port);
}

bool SslSocket::setNonBlocking(bool nonBlocking) {
#ifdef _WIN32
    u_long mode = nonBlocking ? 1 : 0;
    return ioctlsocket(m_socket, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(m_socket, F_GETFL, 0);
    if (flags < 0) return false;
    
    if (nonBlocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }
    
    return fcntl(m_socket, F_SETFL, flags) >= 0;
#endif
}

// =============================================================================
// SslServer Implementation
// =============================================================================

SslServer::SslServer() {
    initializeNetworking();
}

SslServer::~SslServer() {
    stop();
}

bool SslServer::initialize(const std::string& certFile, const std::string& keyFile) {
    return m_ctx.initialize(certFile, keyFile);
}

bool SslServer::listen(uint16_t port, int backlog) {
    // Create socket
    m_listenSocket = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (m_listenSocket == INVALID_SOCKET_VALUE) {
        LOG_ERROR("Failed to create SSL server socket");
        return false;
    }
    
    // Set socket options
    int opt = 1;
    setsockopt(m_listenSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Bind to port
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);
    
    if (::bind(m_listenSocket, (sockaddr*)&addr, sizeof(addr)) < 0) {
        LOG_ERROR("Failed to bind SSL server to port " + std::to_string(port));
#ifdef _WIN32
        closesocket(m_listenSocket);
#else
        ::close(m_listenSocket);
#endif
        m_listenSocket = INVALID_SOCKET_VALUE;
        return false;
    }
    
    // Start listening
    if (::listen(m_listenSocket, backlog) < 0) {
        LOG_ERROR("Failed to listen on SSL server socket");
#ifdef _WIN32
        closesocket(m_listenSocket);
#else
        ::close(m_listenSocket);
#endif
        m_listenSocket = INVALID_SOCKET_VALUE;
        return false;
    }
    
    // Set non-blocking
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(m_listenSocket, FIONBIO, &mode);
#else
    int flags = fcntl(m_listenSocket, F_GETFL, 0);
    fcntl(m_listenSocket, F_SETFL, flags | O_NONBLOCK);
#endif
    
    LOG_INFO("SSL server listening on port " + std::to_string(port));
    return true;
}

std::unique_ptr<SslSocket> SslServer::accept() {
    sockaddr_in clientAddr{};
    socklen_t addrLen = sizeof(clientAddr);
    
    socket_t clientSocket = ::accept(m_listenSocket, (sockaddr*)&clientAddr, &addrLen);
    if (clientSocket == INVALID_SOCKET_VALUE) {
        return nullptr;  // No pending connection
    }
    
    // Create SSL socket and perform handshake
    auto sslSocket = std::make_unique<SslSocket>();
    if (!sslSocket->accept(clientSocket, m_ctx)) {
        // Handshake failed, close the raw socket
#ifdef _WIN32
        closesocket(clientSocket);
#else
        ::close(clientSocket);
#endif
        return nullptr;
    }
    
    return sslSocket;
}

void SslServer::stop() {
    if (m_listenSocket != INVALID_SOCKET_VALUE) {
#ifdef _WIN32
        closesocket(m_listenSocket);
#else
        ::close(m_listenSocket);
#endif
        m_listenSocket = INVALID_SOCKET_VALUE;
    }
}

} // namespace network
} // namespace ds2
