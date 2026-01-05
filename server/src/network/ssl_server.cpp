#include "network/ssl_server.hpp"
#include "utils/logger.hpp"
#include <openssl/ssl.h>
#include <openssl/err.h>

namespace ds2::network {

// SSL info callback to log connection details
static void ssl_info_callback(const SSL* ssl, int where, int ret) {
    const char* str;
    int w = where & ~SSL_ST_MASK;
    
    if (w & SSL_ST_CONNECT) str = "SSL_connect";
    else if (w & SSL_ST_ACCEPT) str = "SSL_accept";
    else str = "undefined";
    
    if (where & SSL_CB_LOOP) {
        LOG_DEBUG("SSL {}: {}", str, SSL_state_string_long(ssl));
    }
    else if (where & SSL_CB_ALERT) {
        str = (where & SSL_CB_READ) ? "read" : "write";
        LOG_WARN("SSL alert {}: {} {}", str, 
            SSL_alert_type_string_long(ret),
            SSL_alert_desc_string_long(ret));
    }
    else if (where & SSL_CB_EXIT) {
        if (ret == 0) {
            LOG_ERROR("SSL {}: failed in {}", str, SSL_state_string_long(ssl));
        }
        else if (ret < 0) {
            LOG_ERROR("SSL {}: error in {}", str, SSL_state_string_long(ssl));
        }
    }
    else if (where & SSL_CB_HANDSHAKE_START) {
        LOG_INFO("SSL handshake started");
    }
    else if (where & SSL_CB_HANDSHAKE_DONE) {
        // Log the negotiated version
        int version = SSL_version(ssl);
        const char* version_str = SSL_get_version(ssl);
        LOG_INFO("SSL handshake done - Version: {} (0x{:04X})", version_str, version);
    }
}

// Message callback for detailed protocol logging (OpenSSL 1.1.1+)
static void ssl_msg_callback(int write_p, int version, int content_type, 
                              const void* buf, size_t len, SSL* ssl, void* arg) {
    (void)ssl;  // unused
    (void)arg;  // unused
    
    const char* version_str;
    switch (version) {
        case SSL2_VERSION:  version_str = "SSLv2"; break;
        case SSL3_VERSION:  version_str = "SSLv3"; break;
        case TLS1_VERSION:  version_str = "TLSv1.0"; break;
        case TLS1_1_VERSION: version_str = "TLSv1.1"; break;
        case TLS1_2_VERSION: version_str = "TLSv1.2"; break;
        case TLS1_3_VERSION: version_str = "TLSv1.3"; break;
        case 0x0100: version_str = "DTLS1.0 (legacy)"; break;
        default: version_str = "Unknown"; break;
    }
    
    const char* content_str;
    switch (content_type) {
        case 20: content_str = "ChangeCipherSpec"; break;
        case 21: content_str = "Alert"; break;
        case 22: content_str = "Handshake"; break;
        case 23: content_str = "ApplicationData"; break;
        default: content_str = "Unknown"; break;
    }
    
    LOG_DEBUG("SSL {} {} version=0x{:04X}({}) content_type={}({}) len={}", 
        write_p ? ">>>" : "<<<",
        write_p ? "sending" : "received",
        version, version_str,
        content_type, content_str,
        len);
    
    // If this is a ClientHello (handshake type 1), parse and log the actual version from the message body
    if (content_type == 22 && len > 0 && !write_p) {
        const unsigned char* data = static_cast<const unsigned char*>(buf);
        if (data[0] == 1 && len >= 6) { // ClientHello (type 1)
            // ClientHello structure: type(1) + length(3) + client_version(2) + random(32) + session_id_len(1) + ...
            uint16_t client_hello_version = (data[4] << 8) | data[5];
            const char* ch_version_str;
            switch (client_hello_version) {
                case SSL2_VERSION:  ch_version_str = "SSLv2"; break;
                case SSL3_VERSION:  ch_version_str = "SSLv3"; break;
                case TLS1_VERSION:  ch_version_str = "TLSv1.0"; break;
                case TLS1_1_VERSION: ch_version_str = "TLSv1.1"; break;
                case TLS1_2_VERSION: ch_version_str = "TLSv1.2"; break;
                case TLS1_3_VERSION: ch_version_str = "TLSv1.3"; break;
                default: ch_version_str = "Unknown"; break;
            }
            
            LOG_INFO(">>> CLIENT HELLO parsed:");
            LOG_INFO("    Record layer version: 0x{:04X} ({})", version, version_str);
            LOG_INFO("    ClientHello body version: 0x{:04X} ({})", client_hello_version, ch_version_str);
            LOG_INFO("    Message length: {} bytes", len);
            
            // Parse more of ClientHello if we have enough data
            if (len >= 38) { // type(1) + len(3) + version(2) + random(32) = 38 bytes minimum
                size_t offset = 38; // Start after random
                
                // Session ID length
                if (offset < len) {
                    uint8_t session_id_len = data[offset++];
                    LOG_INFO("    Session ID length: {}", session_id_len);
                    offset += session_id_len;
                    
                    // Cipher suites
                    if (offset + 2 <= len) {
                        uint16_t cipher_suites_len = (data[offset] << 8) | data[offset + 1];
                        offset += 2;
                        LOG_INFO("    Cipher suites length: {} bytes ({} suites)", 
                            cipher_suites_len, cipher_suites_len / 2);
                        
                        // Log each cipher suite
                        for (size_t i = 0; i < cipher_suites_len && offset + 1 < len; i += 2) {
                            uint16_t cipher = (data[offset] << 8) | data[offset + 1];
                            offset += 2;
                            
                            // Common cipher suite names
                            const char* cipher_name = "Unknown";
                            switch (cipher) {
                                case 0x0000: cipher_name = "TLS_NULL_WITH_NULL_NULL"; break;
                                case 0x0001: cipher_name = "TLS_RSA_WITH_NULL_MD5"; break;
                                case 0x0002: cipher_name = "TLS_RSA_WITH_NULL_SHA"; break;
                                case 0x0004: cipher_name = "TLS_RSA_WITH_RC4_128_MD5"; break;
                                case 0x0005: cipher_name = "TLS_RSA_WITH_RC4_128_SHA"; break;
                                case 0x000A: cipher_name = "TLS_RSA_WITH_3DES_EDE_CBC_SHA"; break;
                                case 0x002F: cipher_name = "TLS_RSA_WITH_AES_128_CBC_SHA"; break;
                                case 0x0033: cipher_name = "TLS_DHE_RSA_WITH_AES_128_CBC_SHA"; break;
                                case 0x0035: cipher_name = "TLS_RSA_WITH_AES_256_CBC_SHA"; break;
                                case 0x0039: cipher_name = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA"; break;
                                case 0x003C: cipher_name = "TLS_RSA_WITH_AES_128_CBC_SHA256"; break;
                                case 0x003D: cipher_name = "TLS_RSA_WITH_AES_256_CBC_SHA256"; break;
                                case 0x009C: cipher_name = "TLS_RSA_WITH_AES_128_GCM_SHA256"; break;
                                case 0x009D: cipher_name = "TLS_RSA_WITH_AES_256_GCM_SHA384"; break;
                                case 0x00FF: cipher_name = "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"; break;
                            }
                            LOG_INFO("      Cipher 0x{:04X}: {}", cipher, cipher_name);
                        }
                    }
                }
            }
            
            // Dump full ClientHello for debugging
            std::string hex_dump;
            for (size_t i = 0; i < len; i++) {
                char hex[4];
                snprintf(hex, sizeof(hex), "%02X ", data[i]);
                hex_dump += hex;
            }
            LOG_INFO("    Full ClientHello: {}", hex_dump);
        }
    }
}

SSLServer::SSLServer(asio::io_context& io_context, const std::string& host, uint16_t port)
    : m_io_context(io_context)
    , m_ssl_context(asio::ssl::context::sslv23)
    , m_acceptor(io_context)
    , m_host(host)
    , m_port(port)
    , m_running(false)
{
}

SSLServer::~SSLServer() {
    stop();
}

bool SSLServer::configureSsl(const std::string& certPath, const std::string& keyPath) {
    try {
        // Dead Space 2 originally used OpenSSL 1.0.0b (2011) but EA may have updated it
        // We bundle OpenSSL 1.1.1 which supports SSLv3/TLS 1.0/1.1/1.2/1.3
        // Note: OpenSSL 1.1.1 completely removed SSLv2 support
        
        // Get the native OpenSSL context handle
        SSL_CTX* ctx = m_ssl_context.native_handle();
        
        // Install debug callbacks to see exactly what version client requests
        SSL_CTX_set_info_callback(ctx, ssl_info_callback);
        SSL_CTX_set_msg_callback(ctx, ssl_msg_callback);
        
        // IMPORTANT: First, clear ALL version-disabling options that may have been set
        // by Asio's context initialization or default_workarounds
        SSL_CTX_clear_options(ctx, 
            SSL_OP_NO_SSLv3 | 
            SSL_OP_NO_TLSv1 | 
            SSL_OP_NO_TLSv1_1 | 
            SSL_OP_NO_TLSv1_2 |
            SSL_OP_NO_TLSv1_3);
        
        // Set minimum protocol version to SSLv3 (original DS2 might use it)
        // Set to 0 which means "lowest supported by this OpenSSL build"
        if (!SSL_CTX_set_min_proto_version(ctx, 0)) {
            LOG_WARN("Could not set min proto version to 0, trying SSL3_VERSION");
            SSL_CTX_set_min_proto_version(ctx, SSL3_VERSION);
        }
        
        // Set maximum to TLS 1.3 (in case DS2 was updated by EA)
        // 0 means "highest supported"
        if (!SSL_CTX_set_max_proto_version(ctx, 0)) {
            LOG_WARN("Could not set max proto version to 0, trying TLS1_3_VERSION");
            SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
        }
        
        // Log what we actually configured
        long min_ver = SSL_CTX_get_min_proto_version(ctx);
        long max_ver = SSL_CTX_get_max_proto_version(ctx);
        LOG_INFO("SSL version range: min=0x{:04X}, max=0x{:04X}", min_ver, max_ver);
        LOG_INFO("Reference: SSL3=0x{:04X}, TLS1.0=0x{:04X}, TLS1.1=0x{:04X}, TLS1.2=0x{:04X}, TLS1.3=0x{:04X}",
            SSL3_VERSION, TLS1_VERSION, TLS1_1_VERSION, TLS1_2_VERSION, TLS1_3_VERSION);
        
        // Log current options
        long opts = SSL_CTX_get_options(ctx);
        LOG_INFO("SSL options before set_options: 0x{:08X}", opts);
        LOG_INFO("  NO_SSLv3: {}, NO_TLSv1: {}, NO_TLSv1_1: {}, NO_TLSv1_2: {}",
            (opts & SSL_OP_NO_SSLv3) ? "YES" : "NO",
            (opts & SSL_OP_NO_TLSv1) ? "YES" : "NO",
            (opts & SSL_OP_NO_TLSv1_1) ? "YES" : "NO",
            (opts & SSL_OP_NO_TLSv1_2) ? "YES" : "NO");
        
        // Enable compatibility options but NOT any NO_* flags
        // SSL_OP_ALL includes various bug workarounds but NOT version disabling
        SSL_CTX_set_options(ctx, SSL_OP_ALL);
        
        // Clear version-disabling options AGAIN after SSL_OP_ALL in case it added any
        SSL_CTX_clear_options(ctx, 
            SSL_OP_NO_SSLv3 | 
            SSL_OP_NO_TLSv1 | 
            SSL_OP_NO_TLSv1_1 | 
            SSL_OP_NO_TLSv1_2);
        
        // Use a cipher list compatible with 2011-era clients
        // Include ALL ciphers for maximum compatibility
        const char* cipherList = "ALL:COMPLEMENTOFALL";
        
        if (!SSL_CTX_set_cipher_list(ctx, cipherList)) {
            LOG_WARN("Could not set cipher list 'ALL:COMPLEMENTOFALL', trying 'ALL'");
            if (!SSL_CTX_set_cipher_list(ctx, "ALL")) {
                LOG_WARN("Could not set cipher list 'ALL', using DEFAULT");
                SSL_CTX_set_cipher_list(ctx, "DEFAULT");
            }
        }
        
        // DON'T use Asio's set_options as it may re-add NO_SSLv3
        // Just set the minimal necessary options directly
        SSL_CTX_set_options(ctx, SSL_OP_SINGLE_DH_USE);
        
        // Final options check
        opts = SSL_CTX_get_options(ctx);
        LOG_INFO("SSL options FINAL: 0x{:08X}", opts);
        LOG_INFO("  NO_SSLv3: {}, NO_TLSv1: {}, NO_TLSv1_1: {}, NO_TLSv1_2: {}",
            (opts & SSL_OP_NO_SSLv3) ? "YES" : "NO",
            (opts & SSL_OP_NO_TLSv1) ? "YES" : "NO",
            (opts & SSL_OP_NO_TLSv1_1) ? "YES" : "NO",
            (opts & SSL_OP_NO_TLSv1_2) ? "YES" : "NO");
        
        m_ssl_context.use_certificate_chain_file(certPath);
        m_ssl_context.use_private_key_file(keyPath, asio::ssl::context::pem);
        
        LOG_INFO("SSL configured with bundled OpenSSL 1.1.1: cert={}, key={}", certPath, keyPath);
        LOG_INFO("SSL/TLS versions enabled: SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3");
        
        return true;
    }
    catch (const std::exception& e) {
        LOG_ERROR("SSL configuration failed: {}", e.what());
        return false;
    }
}

void SSLServer::setConnectionHandler(ConnectionHandler handler) {
    m_connectionHandler = handler;
}

void SSLServer::start() {
    if (m_running) return;
    
    try {
        tcp::endpoint endpoint(asio::ip::make_address(m_host), m_port);
        
        m_acceptor.open(endpoint.protocol());
        m_acceptor.set_option(tcp::acceptor::reuse_address(true));
        m_acceptor.bind(endpoint);
        m_acceptor.listen();
        
        m_running = true;
        LOG_INFO("SSL Server listening on {}:{}", m_host, m_port);
        
        doAccept();
    }
    catch (const std::exception& e) {
        LOG_ERROR("Failed to start SSL server: {}", e.what());
        throw;
    }
}

void SSLServer::stop() {
    if (!m_running) return;
    
    m_running = false;
    
    asio::error_code ec;
    m_acceptor.close(ec);
    
    LOG_INFO("SSL Server stopped on port {}", m_port);
}

void SSLServer::doAccept() {
    if (!m_running) return;
    
    auto socket = std::make_shared<asio::ssl::stream<tcp::socket>>(m_io_context, m_ssl_context);
    
    m_acceptor.async_accept(
        socket->lowest_layer(),
        [this, socket](const asio::error_code& error) {
            handleAccept(socket, error);
        }
    );
}

void SSLServer::handleAccept(
    std::shared_ptr<asio::ssl::stream<tcp::socket>> socket,
    const asio::error_code& error
) {
    if (!m_running) return;
    
    if (!error) {
        std::string remoteAddr = socket->lowest_layer().remote_endpoint().address().to_string();
        uint16_t remotePort = socket->lowest_layer().remote_endpoint().port();
        LOG_INFO("New connection from {}:{}", remoteAddr, remotePort);
        
        // Start SSL handshake
        socket->async_handshake(
            asio::ssl::stream_base::server,
            [this, socket](const asio::error_code& hsError) {
                handleHandshake(socket, hsError);
            }
        );
    }
    else {
        LOG_ERROR("Accept error: {}", error.message());
    }
    
    // Continue accepting
    doAccept();
}

void SSLServer::handleHandshake(
    std::shared_ptr<asio::ssl::stream<tcp::socket>> socket,
    const asio::error_code& error
) {
    if (!error) {
        LOG_DEBUG("SSL handshake successful");
        
        if (m_connectionHandler) {
            m_connectionHandler(socket);
        }
    }
    else {
        LOG_ERROR("SSL handshake failed: {}", error.message());
    }
}

} // namespace ds2::network
