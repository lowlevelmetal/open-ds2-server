#pragma once

#include <string>
#include <vector>
#include <functional>
#include <iostream>
#include <sstream>

namespace ds2 {
namespace test {

/**
 * Simple test framework
 */
class TestRunner {
public:
    struct TestResult {
        std::string name;
        bool passed;
        std::string message;
    };
    
    using TestFunc = std::function<bool(std::string&)>;
    
    static TestRunner& getInstance() {
        static TestRunner instance;
        return instance;
    }
    
    void addTest(const std::string& name, TestFunc func) {
        m_tests.push_back({name, func});
    }
    
    int run() {
        int passed = 0;
        int failed = 0;
        
        std::cout << "\n========================================\n";
        std::cout << "  Running Tests\n";
        std::cout << "========================================\n\n";
        
        for (const auto& [name, func] : m_tests) {
            std::string message;
            bool result = false;
            
            try {
                result = func(message);
            } catch (const std::exception& e) {
                message = std::string("Exception: ") + e.what();
                result = false;
            } catch (...) {
                message = "Unknown exception";
                result = false;
            }
            
            if (result) {
                std::cout << "  ✓ " << name << "\n";
                passed++;
            } else {
                std::cout << "  ✗ " << name << "\n";
                if (!message.empty()) {
                    std::cout << "    └─ " << message << "\n";
                }
                failed++;
            }
            
            m_results.push_back({name, result, message});
        }
        
        std::cout << "\n========================================\n";
        std::cout << "  Results: " << passed << " passed, " << failed << " failed\n";
        std::cout << "========================================\n\n";
        
        return failed > 0 ? 1 : 0;
    }
    
private:
    std::vector<std::pair<std::string, TestFunc>> m_tests;
    std::vector<TestResult> m_results;
};

// Test registration macro
#define TEST(name) \
    static bool test_##name(std::string& _msg); \
    static struct TestRegistrar_##name { \
        TestRegistrar_##name() { \
            ds2::test::TestRunner::getInstance().addTest(#name, test_##name); \
        } \
    } testRegistrar_##name; \
    static bool test_##name([[maybe_unused]] std::string& _msg)

// Assertion macros
#define ASSERT_TRUE(expr) \
    if (!(expr)) { \
        _msg = "Expected true: " #expr; \
        return false; \
    }

#define ASSERT_FALSE(expr) \
    if (expr) { \
        _msg = "Expected false: " #expr; \
        return false; \
    }

#define ASSERT_EQ(a, b) \
    if ((a) != (b)) { \
        _msg = "Assertion failed: " #a " != " #b; \
        return false; \
    }

#define ASSERT_NE(a, b) \
    if ((a) == (b)) { \
        _msg = "Assertion failed: " #a " == " #b; \
        return false; \
    }

#define ASSERT_STREQ(a, b) \
    if (std::string(a) != std::string(b)) { \
        _msg = std::string("Expected \"") + (a) + "\" == \"" + (b) + "\""; \
        return false; \
    }

#define PASS() return true

} // namespace test
} // namespace ds2
