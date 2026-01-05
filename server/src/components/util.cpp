#include "components/util.hpp"
#include "blaze/tdf.hpp"
#include "network/client_connection.hpp"
#include "utils/logger.hpp"

namespace ds2::components {

Util::Util()
    : Component(blaze::ComponentId::Util, "Util")
{
}

std::unique_ptr<blaze::Packet> Util::handlePacket(
    const blaze::Packet& request,
    std::shared_ptr<network::ClientConnection> client
) {
    uint16_t command = request.getCommand();
    
    switch (static_cast<blaze::UtilCommand>(command)) {
        case blaze::UtilCommand::ping:
            return handlePing(request, client);
        
        case blaze::UtilCommand::preAuth:
            return handlePreAuth(request, client);
        
        case blaze::UtilCommand::postAuth:
            return handlePostAuth(request, client);
        
        case blaze::UtilCommand::fetchClientConfig:
            return handleFetchClientConfig(request, client);
        
        default:
            LOG_WARN("[Util] Unknown command: 0x{:04X}", command);
            return createError(request, blaze::BlazeError::ERR_SYSTEM);
    }
}

std::unique_ptr<blaze::Packet> Util::handlePing(
    const blaze::Packet& request,
    std::shared_ptr<network::ClientConnection> client
) {
    LOG_DEBUG("[Util] Ping from {}", client->getRemoteAddress());
    
    // Ping response - just echo back with timestamp
    blaze::TdfBuilder builder;
    builder.integer("STIM", static_cast<int64_t>(time(nullptr)));
    
    auto reply = request.createReply();
    reply->setPayload(builder.build());
    
    return reply;
}

std::unique_ptr<blaze::Packet> Util::handlePreAuth(
    const blaze::Packet& request,
    std::shared_ptr<network::ClientConnection> client
) {
    LOG_INFO("[Util] PreAuth from {}", client->getRemoteAddress());
    
    // PreAuth provides configuration before authentication
    // This includes QoS server address, component configuration, etc.
    
    blaze::TdfBuilder builder;
    builder
        .integer("ANON", 0)           // Anonymous login allowed
        .string("ASRC", "310335")     // Account source
        .intList("CIDS", {1, 25, 4, 27, 28, 6, 7, 9, 10, 11, 30720, 30721, 30722, 30723})  // Component IDs
        .string("CNGN", "")           // 
        .beginStruct("CONF")
            .beginStruct("CONF")
                .string("BWPS", "")   // Bandwidth provisioning server
            .endStruct()
        .endStruct()
        .string("INST", "DS2-PROD")   // Instance name
        .integer("MINR", 0)           // Min client revision
        .string("NASP", "cem_ea_id") // Namespace
        .string("PILD", "")           // 
        .string("PLAT", "pc")         // Platform
        .beginStruct("QOSS")          // QoS settings
            .beginStruct("BWPS")
                .string("PSA", "127.0.0.1")  // Bandwidth server address
                .integer("PSP", 17502)       // Bandwidth server port
                .string("SNA", "ds2-qos")    // Server name
            .endStruct()
            .integer("LNP", 10)        // Local NAT probe
            .beginStruct("LTPS")
                .string("PSA", "127.0.0.1")
                .integer("PSP", 17502)
                .string("SNA", "ds2-qos")
            .endStruct()
            .integer("SVID", 0)
        .endStruct()
        .string("RSRC", "310335")    // Resource
        .string("SVER", "Blaze 3.0") // Server version
        ;
    
    auto reply = request.createReply();
    reply->setPayload(builder.build());
    
    LOG_INFO("[Util] PreAuth response sent");
    
    return reply;
}

std::unique_ptr<blaze::Packet> Util::handlePostAuth(
    const blaze::Packet& request,
    std::shared_ptr<network::ClientConnection> client
) {
    LOG_INFO("[Util] PostAuth from {}", client->getRemoteAddress());
    
    // PostAuth is called after successful authentication
    // Returns telemetry config, user settings, etc.
    
    blaze::TdfBuilder builder;
    builder
        .beginStruct("PSS")   // Post-auth settings
        .endStruct()
        .beginStruct("TELE")  // Telemetry config
            .string("ADRS", "127.0.0.1")  // Telemetry address
            .integer("ANON", 0)
            .string("DPTS", "")
            .string("FILT", "")
            .integer("LOC", 1701729619)   // Locale
            .string("NOOK", "US,CA,MX")
            .integer("PORT", 9988)        // Telemetry port
            .integer("SDLY", 15000)       // Send delay
            .string("SESS", "ds2sess")
            .string("SKEY", "ds2key")
            .integer("SPCT", 75)          // Sample percent
            .string("STIM", "")
        .endStruct()
        .beginStruct("TICK")  // Ticker config
            .string("ADRS", "")
            .integer("PORT", 0)
            .string("SKEY", "")
        .endStruct()
        .beginStruct("UROP")  // User reporting options
            .integer("TMOP", 1)
            .integer("UID", client->getUserId())
        .endStruct();
    
    client->setConnectionState(blaze::ConnectionState::POST_AUTH);
    
    auto reply = request.createReply();
    reply->setPayload(builder.build());
    
    LOG_INFO("[Util] PostAuth response sent");
    
    return reply;
}

std::unique_ptr<blaze::Packet> Util::handleFetchClientConfig(
    const blaze::Packet& request,
    std::shared_ptr<network::ClientConnection> client
) {
    LOG_INFO("[Util] FetchClientConfig from {}", client->getRemoteAddress());
    
    // Client configuration - game-specific settings
    blaze::TdfBuilder builder;
    builder
        .beginStruct("CONF")
            // Game-specific configuration values
            .string("BKCD", "ds2server")        // Backend code
            .integer("ENRQ", 0)                 // Enable requirement
            .string("GNAM", "Dead Space 2")    // Game name
            .integer("MDCT", 32)               // Max data count
            .integer("MXCT", 32)               // Max connection time
        .endStruct();
    
    auto reply = request.createReply();
    reply->setPayload(builder.build());
    
    return reply;
}

} // namespace ds2::components
