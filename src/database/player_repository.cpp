#include "player_repository.hpp"
#include "utils/logger.hpp"

#include <map>
#include <mutex>

namespace ds2 {

// In-memory storage for players (placeholder for real database)
static std::map<uint32_t, PlayerData> s_playersById;
static std::map<std::string, uint32_t> s_playersByName;
static std::mutex s_mutex;
static uint32_t s_nextId = 1;

std::optional<PlayerData> PlayerRepository::getById(uint32_t id) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_playersById.find(id);
    if (it != s_playersById.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::optional<PlayerData> PlayerRepository::getByUsername(const std::string& username) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_playersByName.find(username);
    if (it != s_playersByName.end()) {
        auto playerIt = s_playersById.find(it->second);
        if (playerIt != s_playersById.end()) {
            return playerIt->second;
        }
    }
    return std::nullopt;
}

bool PlayerRepository::create(PlayerData& player) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    if (s_playersByName.find(player.username) != s_playersByName.end()) {
        LOG_WARN("Username already exists: " + player.username);
        return false;
    }
    
    player.id = s_nextId++;
    player.createdAt = std::time(nullptr);
    player.lastLogin = player.createdAt;
    
    s_playersById[player.id] = player;
    s_playersByName[player.username] = player.id;
    
    LOG_INFO("Created player: " + player.username + " (ID: " + std::to_string(player.id) + ")");
    return true;
}

bool PlayerRepository::update(const PlayerData& player) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_playersById.find(player.id);
    if (it == s_playersById.end()) {
        return false;
    }
    
    // Update name mapping if changed
    if (it->second.username != player.username) {
        s_playersByName.erase(it->second.username);
        s_playersByName[player.username] = player.id;
    }
    
    it->second = player;
    return true;
}

bool PlayerRepository::remove(uint32_t id) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_playersById.find(id);
    if (it == s_playersById.end()) {
        return false;
    }
    
    s_playersByName.erase(it->second.username);
    s_playersById.erase(it);
    
    return true;
}

bool PlayerRepository::usernameExists(const std::string& username) {
    std::lock_guard<std::mutex> lock(s_mutex);
    return s_playersByName.find(username) != s_playersByName.end();
}

bool PlayerRepository::updateStats(uint32_t playerId, bool won, int kills, int deaths) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    auto it = s_playersById.find(playerId);
    if (it == s_playersById.end()) {
        return false;
    }
    
    if (won) {
        it->second.wins++;
    } else {
        it->second.losses++;
    }
    
    it->second.kills += kills;
    it->second.deaths += deaths;
    
    // Simple XP system
    it->second.experience += won ? 100 : 25;
    it->second.experience += kills * 10;
    
    // Level up calculation
    uint32_t newLevel = 1 + (it->second.experience / 1000);
    if (newLevel > it->second.level) {
        it->second.level = newLevel;
        LOG_INFO("Player " + it->second.username + " leveled up to " + std::to_string(newLevel));
    }
    
    return true;
}

std::vector<PlayerData> PlayerRepository::getTopByWins(int limit) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    std::vector<PlayerData> result;
    result.reserve(s_playersById.size());
    
    for (const auto& pair : s_playersById) {
        result.push_back(pair.second);
    }
    
    std::sort(result.begin(), result.end(), 
              [](const PlayerData& a, const PlayerData& b) { return a.wins > b.wins; });
    
    if (static_cast<int>(result.size()) > limit) {
        result.resize(limit);
    }
    
    return result;
}

std::vector<PlayerData> PlayerRepository::getTopByKills(int limit) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    std::vector<PlayerData> result;
    result.reserve(s_playersById.size());
    
    for (const auto& pair : s_playersById) {
        result.push_back(pair.second);
    }
    
    std::sort(result.begin(), result.end(), 
              [](const PlayerData& a, const PlayerData& b) { return a.kills > b.kills; });
    
    if (static_cast<int>(result.size()) > limit) {
        result.resize(limit);
    }
    
    return result;
}

std::vector<PlayerData> PlayerRepository::getTopByLevel(int limit) {
    std::lock_guard<std::mutex> lock(s_mutex);
    
    std::vector<PlayerData> result;
    result.reserve(s_playersById.size());
    
    for (const auto& pair : s_playersById) {
        result.push_back(pair.second);
    }
    
    std::sort(result.begin(), result.end(), 
              [](const PlayerData& a, const PlayerData& b) { return a.level > b.level; });
    
    if (static_cast<int>(result.size()) > limit) {
        result.resize(limit);
    }
    
    return result;
}

} // namespace ds2
