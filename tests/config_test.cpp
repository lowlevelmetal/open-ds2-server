#include <gtest/gtest.h>

#include "core/config.hpp"

using namespace opends2;

TEST(Config, DefaultsWhenEmpty) {
    const auto config = parse_config("");
    EXPECT_EQ(config.redirector_port, 42127);
    EXPECT_EQ(config.log_level, log::Level::Info);
}

TEST(Config, ParsesKeysAndComments) {
    const auto config = parse_config(
        "# comment\n"
        "bind_address = 127.0.0.1\n"
        "blaze_port=12345   ; trailing comment\n"
        "\n"
        "public_host = 192.168.1.10\r\n"
        "log_level = trace\n");
    EXPECT_EQ(config.bind_address, "127.0.0.1");
    EXPECT_EQ(config.blaze_port, 12345);
    EXPECT_EQ(config.public_host, "192.168.1.10");
    EXPECT_EQ(config.log_level, log::Level::Trace);
}

TEST(Config, RejectsUnknownKeysAndBadValues) {
    EXPECT_THROW(parse_config("blaze_prot = 1"), std::runtime_error);
    EXPECT_THROW(parse_config("blaze_port = 70000"), std::runtime_error);
    EXPECT_THROW(parse_config("log_level = loud"), std::runtime_error);
    EXPECT_THROW(parse_config("no equals sign"), std::runtime_error);
}
