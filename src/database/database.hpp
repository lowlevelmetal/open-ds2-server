#pragma once

#include <string>
#include <memory>
#include <optional>

namespace ds2 {

/**
 * Database interface
 * Abstract base for different database backends
 */
class Database {
public:
    virtual ~Database() = default;
    
    /**
     * Initialize database connection
     */
    virtual bool initialize(const std::string& connectionString) = 0;
    
    /**
     * Close database connection
     */
    virtual void close() = 0;
    
    /**
     * Check if database is connected
     */
    virtual bool isConnected() const = 0;
    
    /**
     * Execute a query
     */
    virtual bool execute(const std::string& query) = 0;
    
    /**
     * Create the default database
     * @param type "sqlite" or "memory"
     */
    static std::unique_ptr<Database> create(const std::string& type);
};

/**
 * In-memory database for testing/simple deployments
 */
class MemoryDatabase : public Database {
public:
    bool initialize(const std::string& connectionString) override;
    void close() override;
    bool isConnected() const override { return m_connected; }
    bool execute(const std::string& query) override;
    
private:
    bool m_connected{false};
};

} // namespace ds2
