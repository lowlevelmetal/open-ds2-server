#include "database.hpp"
#include "utils/logger.hpp"

namespace ds2 {

std::unique_ptr<Database> Database::create(const std::string& type) {
    if (type == "memory" || type == "mem") {
        return std::make_unique<MemoryDatabase>();
    }
    
    // TODO: Add SQLite support
    // if (type == "sqlite") {
    //     return std::make_unique<SQLiteDatabase>();
    // }
    
    LOG_WARN("Unknown database type: " + type + ", using memory database");
    return std::make_unique<MemoryDatabase>();
}

bool MemoryDatabase::initialize(const std::string& connectionString) {
    (void)connectionString;
    LOG_INFO("Initializing in-memory database");
    m_connected = true;
    return true;
}

void MemoryDatabase::close() {
    m_connected = false;
    LOG_INFO("Memory database closed");
}

bool MemoryDatabase::execute(const std::string& query) {
    (void)query;
    // In-memory database doesn't actually execute SQL
    // It's just a placeholder for the interface
    return m_connected;
}

} // namespace ds2
