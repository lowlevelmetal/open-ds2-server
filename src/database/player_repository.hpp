#pragma once

#include <string>
#include <vector>
#include <optional>
#include <cstdint>

namespace ds2 {

/**
 * Player data structure
 */
struct PlayerData {
    uint32_t id;
    std::string username;
    std::string passwordHash;
    std::string email;
    uint32_t level;
    uint32_t experience;
    uint32_t wins;
    uint32_t losses;
    uint32_t kills;
    uint32_t deaths;
    time_t createdAt;
    time_t lastLogin;
    bool banned;
    std::string banReason;
};

/**
 * Player repository
 * Handles player data persistence
 */
class PlayerRepository {
public:
    /**
     * Get player by ID
     */
    static std::optional<PlayerData> getById(uint32_t id);
    
    /**
     * Get player by username
     */
    static std::optional<PlayerData> getByUsername(const std::string& username);
    
    /**
     * Create a new player
     */
    static bool create(PlayerData& player);
    
    /**
     * Update player data
     */
    static bool update(const PlayerData& player);
    
    /**
     * Delete player
     */
    static bool remove(uint32_t id);
    
    /**
     * Check if username exists
     */
    static bool usernameExists(const std::string& username);
    
    /**
     * Update player stats after a game
     */
    static bool updateStats(uint32_t playerId, bool won, int kills, int deaths);
    
    /**
     * Get top players by various criteria
     */
    static std::vector<PlayerData> getTopByWins(int limit = 10);
    static std::vector<PlayerData> getTopByKills(int limit = 10);
    static std::vector<PlayerData> getTopByLevel(int limit = 10);
};

} // namespace ds2
