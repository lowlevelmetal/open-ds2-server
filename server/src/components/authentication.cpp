#include "components/authentication.hpp"
#include "blaze/tdf.hpp"
#include "network/client_connection.hpp"
#include "utils/logger.hpp"
#include <random>
#include <sstream>
#include <iomanip>

namespace ds2::components {

Authentication::Authentication()
    : Component(blaze::ComponentId::Authentication, "Authentication")
{
}

std::unique_ptr<blaze::Packet> Authentication::handlePacket(
    const blaze::Packet& request,
    std::shared_ptr<network::ClientConnection> client
) {
    uint16_t command = request.getCommand();
    
    switch (static_cast<blaze::AuthCommand>(command)) {
        case blaze::AuthCommand::login:
            return handleLogin(request, client);
        
        case blaze::AuthCommand::silentLogin:
            return handleSilentLogin(request, client);
        
        case blaze::AuthCommand::logout:
            return handleLogout(request, client);
        
        case blaze::AuthCommand::originLogin:
            return handleOriginLogin(request, client);
        
        default:
            LOG_WARN("[Auth] Unknown command: 0x{:04X}", command);
            return createError(request, blaze::BlazeError::ERR_SYSTEM);
    }
}

std::unique_ptr<blaze::Packet> Authentication::handleLogin(
    const blaze::Packet& request,
    std::shared_ptr<network::ClientConnection> client
) {
    LOG_INFO("[Auth] Login request from {}", client->getRemoteAddress());
    
    auto requestTdf = request.getPayloadAsTdf();
    
    // Extract login info (email, password)
    std::string email;
    std::string password;
    
    if (auto it = requestTdf.find("MAIL"); it != requestTdf.end()) {
        if (it->second && it->second->type == blaze::TdfType::String) {
            email = std::get<blaze::TdfString>(it->second->value);
        }
    }
    
    LOG_INFO("[Auth] Login attempt for: {}", email);
    
    // Generate session
    uint64_t sessionId = generateSessionId();
    uint64_t userId = sessionId;  // For now, use session ID as user ID
    std::string authToken = generateAuthToken();
    std::string personaName = email.empty() ? "Player" : email.substr(0, email.find('@'));
    
    // Store session
    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        m_sessions[sessionId] = client;
    }
    
    // Update client state
    client->setSessionId(sessionId);
    client->setUserId(userId);
    client->setPersonaName(personaName);
    client->setConnectionState(blaze::ConnectionState::AUTHENTICATED);
    
    // Build response
    // Response includes:
    // - SESS: Session info
    // - PLST: Persona list
    
    blaze::TdfBuilder builder;
    builder
        .integer("NTOS", 0)       // Number of TOS
        .string("PCTK", authToken) // PC auth token
        .string("PRIV", "")       // Privacy setting
        .beginStruct("SESS")
            .integer("BUID", userId)
            .integer("FRST", 0)
            .string("KEY", authToken)
            .integer("LLOG", 0)
            .string("MAIL", email)
            .beginStruct("PDTL")
                .string("DPTS", "")
                .integer("EXID", 0)
                .integer("GTYP", 0)
                .string("MAIL", email)
                .integer("PID", userId)
                .string("PNAM", personaName)
            .endStruct()
            .integer("UID", userId)
        .endStruct()
        .integer("SPAM", 0)
        .string("THST", "")
        .string("TSUI", "")
        .string("TURI", "");
    
    auto reply = request.createReply();
    reply->setPayload(builder.build());
    
    LOG_INFO("[Auth] Login successful: user={} session={}", personaName, sessionId);
    
    return reply;
}

std::unique_ptr<blaze::Packet> Authentication::handleSilentLogin(
    const blaze::Packet& request,
    std::shared_ptr<network::ClientConnection> client
) {
    LOG_INFO("[Auth] Silent login request from {}", client->getRemoteAddress());
    
    // Silent login uses stored auth token
    auto requestTdf = request.getPayloadAsTdf();
    
    std::string authToken;
    if (auto it = requestTdf.find("AUTH"); it != requestTdf.end()) {
        if (it->second && it->second->type == blaze::TdfType::String) {
            authToken = std::get<blaze::TdfString>(it->second->value);
        }
    }
    
    // For now, accept any token and create new session
    uint64_t sessionId = generateSessionId();
    uint64_t userId = sessionId;
    std::string newToken = generateAuthToken();
    std::string personaName = "Player";
    
    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        m_sessions[sessionId] = client;
    }
    
    client->setSessionId(sessionId);
    client->setUserId(userId);
    client->setPersonaName(personaName);
    client->setConnectionState(blaze::ConnectionState::AUTHENTICATED);
    
    blaze::TdfBuilder builder;
    builder
        .integer("AGUP", 0)
        .string("LDHT", "")
        .integer("NTOS", 0)
        .string("PCTK", newToken)
        .string("PRIV", "")
        .beginStruct("SESS")
            .integer("BUID", userId)
            .integer("FRST", 0)
            .string("KEY", newToken)
            .integer("LLOG", 0)
            .string("MAIL", "")
            .beginStruct("PDTL")
                .string("DPTS", "")
                .integer("EXID", 0)
                .integer("GTYP", 0)
                .string("MAIL", "")
                .integer("PID", userId)
                .string("PNAM", personaName)
            .endStruct()
            .integer("UID", userId)
        .endStruct()
        .integer("SPAM", 0)
        .string("THST", "")
        .string("TSUI", "")
        .string("TURI", "");
    
    auto reply = request.createReply();
    reply->setPayload(builder.build());
    
    LOG_INFO("[Auth] Silent login successful: session={}", sessionId);
    
    return reply;
}

std::unique_ptr<blaze::Packet> Authentication::handleLogout(
    const blaze::Packet& request,
    std::shared_ptr<network::ClientConnection> client
) {
    LOG_INFO("[Auth] Logout request from {}", client->getRemoteAddress());
    
    uint64_t sessionId = client->getSessionId();
    
    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        m_sessions.erase(sessionId);
    }
    
    client->setSessionId(0);
    client->setUserId(0);
    client->setPersonaName("");
    client->setConnectionState(blaze::ConnectionState::CONNECTED);
    
    // Empty response
    auto reply = request.createReply();
    return reply;
}

std::unique_ptr<blaze::Packet> Authentication::handleOriginLogin(
    const blaze::Packet& request,
    std::shared_ptr<network::ClientConnection> client
) {
    LOG_INFO("[Auth] Origin login request from {}", client->getRemoteAddress());
    
    // Origin login is similar to regular login but uses Origin authentication
    // For emulation, we just create a session
    
    auto requestTdf = request.getPayloadAsTdf();
    
    uint64_t sessionId = generateSessionId();
    uint64_t userId = sessionId;
    std::string authToken = generateAuthToken();
    std::string personaName = "OriginPlayer";
    
    {
        std::lock_guard<std::mutex> lock(m_sessionMutex);
        m_sessions[sessionId] = client;
    }
    
    client->setSessionId(sessionId);
    client->setUserId(userId);
    client->setPersonaName(personaName);
    client->setConnectionState(blaze::ConnectionState::AUTHENTICATED);
    
    blaze::TdfBuilder builder;
    builder
        .integer("NTOS", 0)
        .string("PCTK", authToken)
        .string("PRIV", "")
        .beginStruct("SESS")
            .integer("BUID", userId)
            .integer("FRST", 0)
            .string("KEY", authToken)
            .integer("LLOG", 0)
            .string("MAIL", "")
            .beginStruct("PDTL")
                .string("DPTS", "")
                .integer("EXID", 0)
                .integer("GTYP", 0)
                .string("MAIL", "")
                .integer("PID", userId)
                .string("PNAM", personaName)
            .endStruct()
            .integer("UID", userId)
        .endStruct()
        .integer("SPAM", 0)
        .string("THST", "")
        .string("TSUI", "")
        .string("TURI", "");
    
    auto reply = request.createReply();
    reply->setPayload(builder.build());
    
    LOG_INFO("[Auth] Origin login successful: session={}", sessionId);
    
    return reply;
}

uint64_t Authentication::generateSessionId() {
    std::lock_guard<std::mutex> lock(m_sessionMutex);
    return m_nextSessionId++;
}

std::string Authentication::generateAuthToken() {
    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    static std::uniform_int_distribution<uint64_t> dis;
    
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    ss << std::setw(16) << dis(gen);
    ss << std::setw(16) << dis(gen);
    
    return ss.str();
}

} // namespace ds2::components
