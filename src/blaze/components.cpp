#include "components.hpp"
#include "blaze_codec.hpp"
#include "tdf.hpp"
#include "core/session.hpp"
#include "utils/logger.hpp"

#include <ctime>

namespace ds2 {
namespace blaze {

// =============================================================================
// Redirector Handler
// =============================================================================

void RedirectorHandler::handleGetServerInstance(std::shared_ptr<Session> session, Packet& packet) {
    LOG_INFO("Redirector: GetServerInstance from " + session->getAddress());
    
    // Parse request to get client info
    // TdfReader reader(packet.payload);
    // ... parse NAME, PLAT, VERS, etc.
    
    // Create response with server address
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    
    // Server address info
    writer.startStruct("ADDR");
    writer.writeInteger("IP", 0x7F000001);  // 127.0.0.1 - should be configurable
    writer.writeInteger("PORT", 10041);      // Game server port
    writer.endStruct();
    
    // Secure connection flag
    writer.writeInteger("SECU", 0);  // 0 = not secure, 1 = SSL
    
    // XDNS - external DNS?
    writer.writeInteger("XDNS", 0);
    
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
}

void RedirectorHandler::handleGetServerList(std::shared_ptr<Session> session, Packet& packet) {
    LOG_INFO("Redirector: GetServerList from " + session->getAddress());
    
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    
    // Empty server list for now
    writer.startList("SRVS", TdfType::Struct, 0);
    writer.endList();
    
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
}

void RedirectorHandler::registerHandlers() {
    auto& router = BlazeRouter::getInstance();
    router.registerHandler(ComponentId::Redirector, 
        static_cast<uint16_t>(RedirectorCommand::GetServerInstance),
        handleGetServerInstance);
    router.registerHandler(ComponentId::Redirector,
        static_cast<uint16_t>(RedirectorCommand::GetServerList),
        handleGetServerList);
    LOG_INFO("Redirector handlers registered");
}

// =============================================================================
// Authentication Handler
// =============================================================================

void AuthenticationHandler::handlePreAuth(std::shared_ptr<Session> session, Packet& packet) {
    LOG_INFO("Auth: PreAuth from " + session->getAddress());
    
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    
    // Configuration data
    writer.writeInteger("ANON", 0);  // Anonymous login allowed
    writer.writeString("ASRC", "300294");  // Auth source
    writer.writeInteger("CIDS", 1);  // Client ID
    
    // Persona config
    writer.startStruct("CONF");
    writer.writeInteger("CONF", 1);
    writer.endStruct();
    
    // Platform
    writer.writeString("INST", "deadspace2-pc");
    writer.writeInteger("MINR", 0);
    writer.writeString("NASP", "cem_ea_id");
    writer.writeString("PILD", "");
    writer.writeString("PLAT", "pc");  // Platform
    
    // Persona namespace
    writer.writeString("PTAG", "");
    
    // QoS server
    writer.startStruct("QOSS");
    writer.startStruct("BWPS");
    writer.writeString("PSA", "");
    writer.writeInteger("PSP", 0);
    writer.writeString("SNA", "");
    writer.endStruct();
    writer.writeInteger("LNP", 10);
    writer.startMap("LTPS", TdfType::String, TdfType::Struct, 0);
    writer.endMap();
    writer.writeInteger("SVID", 0);
    writer.endStruct();
    
    // Server instance name
    writer.writeString("RSRC", "300294");
    writer.writeString("SVER", "Arson5.0.0");
    
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
}

void AuthenticationHandler::handleLogin(std::shared_ptr<Session> session, Packet& packet) {
    LOG_INFO("Auth: Login from " + session->getAddress());
    
    // Parse login request
    std::string email;
    std::string password;
    
    if (!packet.payload.empty()) {
        TdfReader reader(packet.payload);
        std::string label;
        TdfType type;
        
        while (reader.readTag(label, type)) {
            if (label == "MAIL" && type == TdfType::String) {
                email = reader.readString();
            } else if (label == "PASS" && type == TdfType::String) {
                password = reader.readString();
            } else {
                reader.skipValue(type);
            }
        }
    }
    
    LOG_INFO("Login attempt: " + email);
    
    // For open server, accept all logins
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    
    // Generate user/session IDs
    static uint64_t nextUserId = 1000;
    uint64_t userId = nextUserId++;
    uint64_t sessionId = std::time(nullptr) * 1000 + userId;
    
    // Session info
    writer.writeInteger("AGUP", 0);  // Age up required
    writer.writeString("LDHT", "");  // Last disconnect reason
    writer.writeInteger("NTOS", 0);  // Need TOS
    writer.writeString("PCTK", "");  // PC ticket
    
    // Player info
    writer.startStruct("SESS");
    writer.writeInteger("BUID", userId);
    writer.writeInteger("FRST", 0);
    writer.writeString("KEY", "session_" + std::to_string(sessionId));
    writer.writeInteger("LLOG", std::time(nullptr));
    writer.writeString("MAIL", email);
    
    // Persona details
    writer.startStruct("PDTL");
    writer.writeString("DSNM", email.substr(0, email.find('@')));  // Display name
    writer.writeInteger("LAST", std::time(nullptr));
    writer.writeInteger("PID", userId);
    writer.writeInteger("STAS", 0);
    writer.writeInteger("XREF", 0);
    writer.writeInteger("XTYP", 0);
    writer.endStruct();
    
    writer.writeInteger("UID", userId);
    writer.endStruct();
    
    writer.writeInteger("SPAM", 0);
    writer.writeString("THST", "");
    writer.writeString("TSUI", "");
    writer.writeString("TURI", "");
    
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
    
    // Store user info in session
    session->setPlayerId(static_cast<uint32_t>(userId));
    session->setPlayerName(email.substr(0, email.find('@')));
    session->setState(SessionState::Authenticated);
}

void AuthenticationHandler::handleSilentLogin(std::shared_ptr<Session> session, Packet& packet) {
    LOG_INFO("Auth: SilentLogin from " + session->getAddress());
    // Treat same as regular login for now
    handleLogin(session, packet);
}

void AuthenticationHandler::handleLogout(std::shared_ptr<Session> session, Packet& packet) {
    LOG_INFO("Auth: Logout from " + session->getPlayerName());
    
    Packet reply = BlazeCodec::createReply(packet);
    // Empty response is fine
    session->sendBlazePacket(reply);
    
    session->setState(SessionState::Connected);
}

void AuthenticationHandler::handleGetAuthToken(std::shared_ptr<Session> session, Packet& packet) {
    LOG_INFO("Auth: GetAuthToken from " + session->getPlayerName());
    
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    
    // Return a dummy auth token
    writer.writeString("AUTH", "dummy_auth_token_" + std::to_string(session->getPlayerId()));
    
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
}

void AuthenticationHandler::handleListPersonas(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_INFO("Auth: ListPersonas from " + session->getPlayerName());
    
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    
    // Return single persona (the logged in user)
    writer.startList("PSLST", TdfType::Struct, 1);
    
    // Persona entry
    writer.writeString("DSNM", session->getPlayerName());
    writer.writeInteger("LAST", std::time(nullptr));
    writer.writeInteger("PID", session->getPlayerId());
    writer.writeInteger("STAS", 0);
    writer.writeInteger("XREF", 0);
    writer.writeInteger("XTYP", 0);
    
    writer.endList();
    
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
}

void AuthenticationHandler::handleLoginPersona(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_INFO("Auth: LoginPersona from " + session->getPlayerName());
    
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    
    // Session key
    writer.writeInteger("BUID", session->getPlayerId());
    writer.writeString("PNAM", session->getPlayerName());
    writer.writeInteger("PID", session->getPlayerId());
    
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
}

void AuthenticationHandler::registerHandlers() {
    auto& router = BlazeRouter::getInstance();
    
    router.registerHandler(ComponentId::Authentication,
        static_cast<uint16_t>(AuthCommand::Login),
        handleLogin);
    router.registerHandler(ComponentId::Authentication,
        static_cast<uint16_t>(AuthCommand::SilentLogin),
        handleSilentLogin);
    router.registerHandler(ComponentId::Authentication,
        static_cast<uint16_t>(AuthCommand::Logout),
        handleLogout);
    router.registerHandler(ComponentId::Authentication,
        static_cast<uint16_t>(AuthCommand::GetAuthToken),
        handleGetAuthToken);
    router.registerHandler(ComponentId::Authentication,
        static_cast<uint16_t>(AuthCommand::ListPersonas),
        handleListPersonas);
    router.registerHandler(ComponentId::Authentication,
        static_cast<uint16_t>(AuthCommand::LoginPersona),
        handleLoginPersona);
        
    LOG_INFO("Authentication handlers registered");
}

// =============================================================================
// Util Handler
// =============================================================================

void UtilHandler::handlePing(std::shared_ptr<Session> session, Packet& packet) {
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    writer.writeInteger("STIM", std::time(nullptr));
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
}

void UtilHandler::handleFetchClientConfig(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_DEBUG("Util: FetchClientConfig from " + session->getAddress());
    
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    
    // Configuration map
    writer.startMap("CONF", TdfType::String, TdfType::String, 0);
    writer.endMap();
    
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
}

void UtilHandler::handlePreAuth(std::shared_ptr<Session> session, Packet& packet) {
    // Delegate to Auth handler
    AuthenticationHandler::handlePreAuth(session, packet);
}

void UtilHandler::handlePostAuth(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_DEBUG("Util: PostAuth from " + session->getPlayerName());
    
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    
    // Telemetry config
    writer.startStruct("TELE");
    writer.writeString("ADRS", "");
    writer.writeInteger("ANON", 0);
    writer.writeString("DPTS", "");
    writer.writeString("FILT", "");
    writer.writeInteger("LOC", 0);
    writer.writeString("NOOK", "");
    writer.writeInteger("PORT", 0);
    writer.writeInteger("SDLY", 0);
    writer.writeString("SESS", "");
    writer.writeString("SKEY", "");
    writer.writeInteger("SPCT", 0);
    writer.endStruct();
    
    // Ticker server
    writer.startStruct("TICK");
    writer.writeString("ADRS", "");
    writer.writeInteger("PORT", 0);
    writer.writeString("SKEY", "");
    writer.endStruct();
    
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
}

void UtilHandler::handleUserSettingsLoad(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_DEBUG("Util: UserSettingsLoad from " + session->getPlayerName());
    
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    
    // Return empty settings
    writer.writeString("DATA", "");
    
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
}

void UtilHandler::handleUserSettingsSave(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_DEBUG("Util: UserSettingsSave from " + session->getPlayerName());
    
    // Just acknowledge
    Packet reply = BlazeCodec::createReply(packet);
    session->sendBlazePacket(reply);
}

void UtilHandler::handleSetClientData(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_DEBUG("Util: SetClientData from " + session->getAddress());
    
    Packet reply = BlazeCodec::createReply(packet);
    session->sendBlazePacket(reply);
}

void UtilHandler::registerHandlers() {
    auto& router = BlazeRouter::getInstance();
    
    router.registerHandler(ComponentId::Util,
        static_cast<uint16_t>(UtilCommand::Ping),
        handlePing);
    router.registerHandler(ComponentId::Util,
        static_cast<uint16_t>(UtilCommand::FetchClientConfig),
        handleFetchClientConfig);
    router.registerHandler(ComponentId::Util,
        static_cast<uint16_t>(UtilCommand::PreAuth),
        handlePreAuth);
    router.registerHandler(ComponentId::Util,
        static_cast<uint16_t>(UtilCommand::PostAuth),
        handlePostAuth);
    router.registerHandler(ComponentId::Util,
        static_cast<uint16_t>(UtilCommand::UserSettingsLoad),
        handleUserSettingsLoad);
    router.registerHandler(ComponentId::Util,
        static_cast<uint16_t>(UtilCommand::UserSettingsSave),
        handleUserSettingsSave);
    router.registerHandler(ComponentId::Util,
        static_cast<uint16_t>(UtilCommand::SetClientData),
        handleSetClientData);
        
    LOG_INFO("Util handlers registered");
}

// =============================================================================
// GameManager Handler
// =============================================================================

void GameManagerHandler::handleCreateGame(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_INFO("GameManager: CreateGame from " + session->getPlayerName());
    
    // TODO: Implement game creation
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    
    static uint64_t nextGameId = 1;
    uint64_t gameId = nextGameId++;
    
    writer.writeInteger("GID", gameId);
    
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
}

void GameManagerHandler::handleJoinGame(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_INFO("GameManager: JoinGame from " + session->getPlayerName());
    
    // TODO: Implement game joining
    Packet reply = BlazeCodec::createReply(packet);
    session->sendBlazePacket(reply);
}

void GameManagerHandler::handleRemovePlayer(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_INFO("GameManager: RemovePlayer from " + session->getPlayerName());
    
    Packet reply = BlazeCodec::createReply(packet);
    session->sendBlazePacket(reply);
}

void GameManagerHandler::handleStartMatchmaking(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_INFO("GameManager: StartMatchmaking from " + session->getPlayerName());
    
    // TODO: Implement matchmaking
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    
    writer.writeInteger("MSID", 0);  // Matchmaking session ID
    
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
}

void GameManagerHandler::handleCancelMatchmaking(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_INFO("GameManager: CancelMatchmaking from " + session->getPlayerName());
    
    Packet reply = BlazeCodec::createReply(packet);
    session->sendBlazePacket(reply);
}

void GameManagerHandler::handleListGames(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_DEBUG("GameManager: ListGames from " + session->getPlayerName());
    
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    
    // Empty game list
    writer.startList("GLST", TdfType::Struct, 0);
    writer.endList();
    
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
}

void GameManagerHandler::handleGetGameListSubscription(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_DEBUG("GameManager: GetGameListSubscription from " + session->getPlayerName());
    
    Packet reply = BlazeCodec::createReply(packet);
    session->sendBlazePacket(reply);
}

void GameManagerHandler::handleAdvanceGameState(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_DEBUG("GameManager: AdvanceGameState from " + session->getPlayerName());
    
    Packet reply = BlazeCodec::createReply(packet);
    session->sendBlazePacket(reply);
}

void GameManagerHandler::handleSetGameAttributes(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_DEBUG("GameManager: SetGameAttributes from " + session->getPlayerName());
    
    Packet reply = BlazeCodec::createReply(packet);
    session->sendBlazePacket(reply);
}

void GameManagerHandler::handleUpdateMeshConnection(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_DEBUG("GameManager: UpdateMeshConnection from " + session->getPlayerName());
    
    Packet reply = BlazeCodec::createReply(packet);
    session->sendBlazePacket(reply);
}

void GameManagerHandler::registerHandlers() {
    auto& router = BlazeRouter::getInstance();
    
    router.registerHandler(ComponentId::GameManager,
        static_cast<uint16_t>(GameManagerCommand::CreateGame),
        handleCreateGame);
    router.registerHandler(ComponentId::GameManager,
        static_cast<uint16_t>(GameManagerCommand::JoinGame),
        handleJoinGame);
    router.registerHandler(ComponentId::GameManager,
        static_cast<uint16_t>(GameManagerCommand::RemovePlayer),
        handleRemovePlayer);
    router.registerHandler(ComponentId::GameManager,
        static_cast<uint16_t>(GameManagerCommand::StartMatchmaking),
        handleStartMatchmaking);
    router.registerHandler(ComponentId::GameManager,
        static_cast<uint16_t>(GameManagerCommand::CancelMatchmaking),
        handleCancelMatchmaking);
    router.registerHandler(ComponentId::GameManager,
        static_cast<uint16_t>(GameManagerCommand::ListGames),
        handleListGames);
    router.registerHandler(ComponentId::GameManager,
        static_cast<uint16_t>(GameManagerCommand::GetGameListSubscription),
        handleGetGameListSubscription);
    router.registerHandler(ComponentId::GameManager,
        static_cast<uint16_t>(GameManagerCommand::AdvanceGameState),
        handleAdvanceGameState);
    router.registerHandler(ComponentId::GameManager,
        static_cast<uint16_t>(GameManagerCommand::SetGameAttributes),
        handleSetGameAttributes);
    router.registerHandler(ComponentId::GameManager,
        static_cast<uint16_t>(GameManagerCommand::UpdateMeshConnection),
        handleUpdateMeshConnection);
        
    LOG_INFO("GameManager handlers registered");
}

// =============================================================================
// Stats Handler
// =============================================================================

void StatsHandler::handleGetStats(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_DEBUG("Stats: GetStats from " + session->getPlayerName());
    
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    
    // Empty stats for now
    writer.startList("STAT", TdfType::Struct, 0);
    writer.endList();
    
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
}

void StatsHandler::handleGetStatsByGroup(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_DEBUG("Stats: GetStatsByGroup from " + session->getPlayerName());
    
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    
    writer.startList("STAT", TdfType::Struct, 0);
    writer.endList();
    
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
}

void StatsHandler::handleGetLeaderboard(std::shared_ptr<Session> session, Packet& packet) {
    (void)packet;
    LOG_DEBUG("Stats: GetLeaderboard from " + session->getPlayerName());
    
    Packet reply = BlazeCodec::createReply(packet);
    TdfWriter writer;
    
    // Empty leaderboard
    writer.startList("LDLS", TdfType::Struct, 0);
    writer.endList();
    
    reply.payload = writer.take();
    session->sendBlazePacket(reply);
}

void StatsHandler::registerHandlers() {
    auto& router = BlazeRouter::getInstance();
    
    router.registerHandler(ComponentId::Stats,
        static_cast<uint16_t>(StatsCommand::GetStats),
        handleGetStats);
    router.registerHandler(ComponentId::Stats,
        static_cast<uint16_t>(StatsCommand::GetStatsByGroup),
        handleGetStatsByGroup);
    router.registerHandler(ComponentId::Stats,
        static_cast<uint16_t>(StatsCommand::GetLeaderboard),
        handleGetLeaderboard);
        
    LOG_INFO("Stats handlers registered");
}

// =============================================================================
// Register All
// =============================================================================

void registerAllHandlers() {
    LOG_INFO("Registering Blaze component handlers...");
    
    RedirectorHandler::registerHandlers();
    AuthenticationHandler::registerHandlers();
    UtilHandler::registerHandlers();
    GameManagerHandler::registerHandlers();
    StatsHandler::registerHandlers();
    
    LOG_INFO("All Blaze handlers registered");
}

} // namespace blaze
} // namespace ds2
