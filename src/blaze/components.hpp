#pragma once

#include <memory>
#include "blaze_types.hpp"

namespace ds2 {

class Session;

namespace blaze {

/**
 * Redirector component handler
 * First point of contact - directs client to appropriate game server
 */
class RedirectorHandler {
public:
    /**
     * Handle GetServerInstance request
     * Returns server address for client to connect to
     */
    static void handleGetServerInstance(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle GetServerList request
     */
    static void handleGetServerList(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Register all redirector handlers
     */
    static void registerHandlers();
};

/**
 * Authentication component handler
 */
class AuthenticationHandler {
public:
    /**
     * Handle PreAuth request (pre-login configuration)
     */
    static void handlePreAuth(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle Login request
     */
    static void handleLogin(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle SilentLogin request (auto-login)
     */
    static void handleSilentLogin(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle Logout request
     */
    static void handleLogout(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle GetAuthToken request
     */
    static void handleGetAuthToken(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle ListPersonas request
     */
    static void handleListPersonas(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle LoginPersona request
     */
    static void handleLoginPersona(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Register all authentication handlers
     */
    static void registerHandlers();
};

/**
 * Util component handler
 */
class UtilHandler {
public:
    /**
     * Handle Ping request
     */
    static void handlePing(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle FetchClientConfig request
     */
    static void handleFetchClientConfig(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle PreAuth request
     */
    static void handlePreAuth(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle PostAuth request
     */
    static void handlePostAuth(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle UserSettingsLoad request
     */
    static void handleUserSettingsLoad(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle UserSettingsSave request
     */
    static void handleUserSettingsSave(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle SetClientData request
     */
    static void handleSetClientData(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Register all util handlers
     */
    static void registerHandlers();
};

/**
 * GameManager component handler
 */
class GameManagerHandler {
public:
    /**
     * Handle CreateGame request
     */
    static void handleCreateGame(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle JoinGame request
     */
    static void handleJoinGame(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle LeaveGame / RemovePlayer request
     */
    static void handleRemovePlayer(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle StartMatchmaking request
     */
    static void handleStartMatchmaking(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle CancelMatchmaking request
     */
    static void handleCancelMatchmaking(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle ListGames request
     */
    static void handleListGames(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle GetGameListSubscription request
     */
    static void handleGetGameListSubscription(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle AdvanceGameState request
     */
    static void handleAdvanceGameState(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle SetGameAttributes request
     */
    static void handleSetGameAttributes(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle UpdateMeshConnection request
     */
    static void handleUpdateMeshConnection(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Register all game manager handlers
     */
    static void registerHandlers();
};

/**
 * Stats component handler
 */
class StatsHandler {
public:
    /**
     * Handle GetStats request
     */
    static void handleGetStats(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle GetStatsByGroup request
     */
    static void handleGetStatsByGroup(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Handle GetLeaderboard request
     */
    static void handleGetLeaderboard(std::shared_ptr<Session> session, Packet& packet);
    
    /**
     * Register all stats handlers
     */
    static void registerHandlers();
};

/**
 * Register all Blaze component handlers
 */
void registerAllHandlers();

} // namespace blaze
} // namespace ds2
