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
    LOG_INFO("OpenSSL initialized (bundled 1.1.1 with legacy support)");
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

// SSL handshake debug callback
static void sslInfoCallback(const SSL* ssl, int where, int ret) {
    const char* str;
    int w = where & ~SSL_ST_MASK;

    if (w & SSL_ST_CONNECT) str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT) str = "SSL_accept";
    else str = "undefined";

    if (where & SSL_CB_LOOP) {
        LOG_INFO(std::string("SSL state: ") + str + " - " + SSL_state_string_long(ssl));
        
        // After reading client hello, log the selected cipher
        const char* state = SSL_state_string_long(ssl);
        if (strstr(state, "read client hello") != nullptr) {
            const SSL_CIPHER* cipher = SSL_get_current_cipher(ssl);
            if (cipher) {
                LOG_INFO(std::string("  Selected cipher: ") + SSL_CIPHER_get_name(cipher));
            }
            LOG_INFO(std::string("  Protocol version: ") + SSL_get_version(ssl));
            
            // Log client's offered ciphers
            STACK_OF(SSL_CIPHER)* clientCiphers = SSL_get_client_ciphers(ssl);
            if (clientCiphers) {
                int count = sk_SSL_CIPHER_num(clientCiphers);
                LOG_INFO("  Client offered " + std::to_string(count) + " ciphers:");
                for (int i = 0; i < count && i < 15; i++) {
                    const SSL_CIPHER* c = sk_SSL_CIPHER_value(clientCiphers, i);
                    LOG_INFO("    " + std::string(SSL_CIPHER_get_name(c)));
                }
            }
        }
    } else if (where & SSL_CB_ALERT) {
        str = (where & SSL_CB_READ) ? "read" : "write";
        LOG_WARN(std::string("SSL alert [") + str + "]: " + 
                 SSL_alert_type_string_long(ret) + ":" + 
                 SSL_alert_desc_string_long(ret));
    } else if (where & SSL_CB_EXIT) {
        if (ret == 0) {
            LOG_ERROR(std::string("SSL: ") + str + " failed in " + SSL_state_string_long(ssl));
        } else if (ret < 0) {
            LOG_WARN(std::string("SSL: ") + str + " error in " + SSL_state_string_long(ssl));
        }
    } else if (where & SSL_CB_HANDSHAKE_START) {
        LOG_INFO("SSL handshake starting...");
        // Log the client's version
        LOG_INFO(std::string("  Client protocol: ") + SSL_get_version(ssl));
    } else if (where & SSL_CB_HANDSHAKE_DONE) {
        LOG_INFO("SSL handshake completed!");
        LOG_INFO(std::string("  Protocol: ") + SSL_get_version(ssl));
        LOG_INFO(std::string("  Cipher: ") + SSL_get_cipher_name(ssl));
    }
}

bool SslContext::initialize(const std::string& certFile, const std::string& keyFile) {
    // Create SSL context using SSLv23 method which supports SSLv3, TLS 1.0, 1.1, 1.2
    // This is needed for Dead Space 2 which uses OpenSSL 1.0.0b
    m_ctx = SSL_CTX_new(SSLv23_server_method());
    if (!m_ctx) {
        LOG_ERROR("Failed to create SSL context: " + getLastError());
        return false;
    }
    
    // Enable handshake debugging
    SSL_CTX_set_info_callback(m_ctx, sslInfoCallback);
    
    // Allow SSLv3 and TLS 1.0 for OpenSSL 1.0.0b game client
    // Only disable SSLv2 (truly broken) and newer TLS versions the client won't understand
    long options = SSL_OP_NO_SSLv2 | SSL_OP_NO_TLSv1_1 | SSL_OP_NO_TLSv1_2 | SSL_OP_NO_TLSv1_3;
    // Disable features that might confuse old clients
    options |= SSL_OP_NO_TICKET;  // No session tickets
    options |= SSL_OP_NO_COMPRESSION;  // No compression
    options |= SSL_OP_LEGACY_SERVER_CONNECT;  // Legacy renegotiation
    SSL_CTX_set_options(m_ctx, options);
    
    // Set minimum protocol to SSLv3, max to TLS 1.0 (our bundled OpenSSL 1.1.1 supports this)
    SSL_CTX_set_min_proto_version(m_ctx, SSL3_VERSION);
    SSL_CTX_set_max_proto_version(m_ctx, TLS1_VERSION);
    
    // Explicitly disable TLS 1.3 ciphersuites (separate from cipher list in OpenSSL 1.1.1)
    SSL_CTX_set_ciphersuites(m_ctx, "");  // Empty string disables all TLS 1.3 suites
    
    // Use classic RSA ciphers that OpenSSL 1.0.0b definitely supports
    // The game client likely uses RSA key exchange with RC4 or AES
    // Order: Most compatible first, only SSLv3/TLS1.0 ciphers
    // Don't use @STRENGTH which reorders by key length
    const char* cipherList = 
        "RC4-SHA:RC4-MD5:"                              // RC4 ciphers (fast, widely supported in 2010)
        "AES128-SHA:AES256-SHA:"                        // AES-CBC with SHA1
        "DES-CBC3-SHA:"                                 // 3DES fallback  
        "DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA:"        // DHE variants
        "EDH-RSA-DES-CBC3-SHA:"                         // EDH 3DES
        "!aNULL:!eNULL:!EXPORT:!MD5";                   // Security exclusions
    
    if (!SSL_CTX_set_cipher_list(m_ctx, cipherList)) {
        LOG_WARN("Failed to set preferred cipher list, using defaults");
        SSL_CTX_set_cipher_list(m_ctx, "ALL:!aNULL:!eNULL:@STRENGTH");
    }
    
    // Log available ciphers
    SSL* tmpSsl = SSL_new(m_ctx);
    if (tmpSsl) {
        STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(tmpSsl);
        if (ciphers) {
            int count = sk_SSL_CIPHER_num(ciphers);
            LOG_INFO("Available ciphers (" + std::to_string(count) + "):");
            for (int i = 0; i < count && i < 10; i++) {
                const SSL_CIPHER* c = sk_SSL_CIPHER_value(ciphers, i);
                LOG_INFO("  " + std::string(SSL_CIPHER_get_name(c)));
            }
            if (count > 10) LOG_INFO("  ... and " + std::to_string(count - 10) + " more");
        }
        SSL_free(tmpSsl);
    }
    
    // Disable client certificate verification (we're the server)
    SSL_CTX_set_verify(m_ctx, SSL_VERIFY_NONE, nullptr);
    
    LOG_INFO("SSL configured for SSLv3/TLS1.0 with RC4/AES ciphers");
    
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
        
        // Get more detailed error info
        unsigned long errCode = ERR_get_error();
        char errBuf[256];
        ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
        
        // Also check errno for syscall errors
        int sysErr = errno;
        
        LOG_ERROR("SSL handshake failed:");
        LOG_ERROR("  SSL_get_error: " + std::to_string(err));
        LOG_ERROR("  ERR_get_error: " + std::string(errBuf));
        LOG_ERROR("  errno: " + std::to_string(sysErr) + " (" + strerror(sysErr) + ")");
        
        // Dump the full error queue
        while ((errCode = ERR_get_error()) != 0) {
            ERR_error_string_n(errCode, errBuf, sizeof(errBuf));
            LOG_ERROR("  Additional error: " + std::string(errBuf));
        }
        
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
