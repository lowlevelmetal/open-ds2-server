cmake_minimum_required(VERSION 3.16)
project(open-ds2-server 
    VERSION 0.1.0
    DESCRIPTION "Open source Dead Space 2 server emulator"
    LANGUAGES CXX
)

# C++17 standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Build type
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler warnings
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
    add_compile_options(-Wall -Wextra -Wpedantic)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0)
    else()
        add_compile_options(-O3)
    endif()
endif()

# Output directories
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# Find required packages
find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/src)

# Source files
set(CORE_SOURCES
    src/core/server.cpp
    src/core/session.cpp
    src/core/config.cpp
)

set(NETWORK_SOURCES
    src/network/tcp_server.cpp
    src/network/udp_server.cpp
    src/network/packet.cpp
    src/network/packet_handler.cpp
    src/network/ssl_socket.cpp
)

set(PROTOCOL_SOURCES
    src/protocol/ds2_protocol.cpp
    src/protocol/auth_handler.cpp
    src/protocol/lobby_handler.cpp
    src/protocol/game_handler.cpp
)

set(UTILS_SOURCES
    src/utils/logger.cpp
    src/utils/crypto.cpp
    src/utils/buffer.cpp
)

set(DATABASE_SOURCES
    src/database/database.cpp
    src/database/player_repository.cpp
)

set(BLAZE_SOURCES
    src/blaze/tdf.cpp
    src/blaze/blaze_codec.cpp
    src/blaze/components.cpp
    src/blaze/blaze_server.cpp
)

# Create the server executable
add_executable(ds2-server
    src/main.cpp
    ${CORE_SOURCES}
    ${NETWORK_SOURCES}
    ${PROTOCOL_SOURCES}
    ${UTILS_SOURCES}
    ${DATABASE_SOURCES}
    ${BLAZE_SOURCES}
)

target_link_libraries(ds2-server PRIVATE
    Threads::Threads
    OpenSSL::SSL
    OpenSSL::Crypto
)

# Platform-specific linking
if(UNIX AND NOT APPLE)
    target_link_libraries(ds2-server PRIVATE rt)
endif()

# Install rules
install(TARGETS ds2-server RUNTIME DESTINATION bin)
install(DIRECTORY config/ DESTINATION etc/ds2-server)

# Testing
option(BUILD_TESTS "Build tests" ON)
if(BUILD_TESTS)
    enable_testing()
    
    # Test executable
    add_executable(ds2-tests
        tests/run_tests.cpp
    )
    
    target_include_directories(ds2-tests PRIVATE
        ${CMAKE_SOURCE_DIR}/src
        ${CMAKE_SOURCE_DIR}/tests
    )
    
    # Link test executable with required object files
    target_sources(ds2-tests PRIVATE
        src/blaze/tdf.cpp
        src/blaze/blaze_codec.cpp
        src/utils/logger.cpp
    )
    
    target_link_libraries(ds2-tests PRIVATE
        Threads::Threads
    )
    
    # Add test
    add_test(NAME unit_tests COMMAND ds2-tests)
endif()

# Print configuration summary
message(STATUS "")
message(STATUS "=== open-ds2-server Configuration ===")
message(STATUS "Version:      ${PROJECT_VERSION}")
message(STATUS "Build type:   ${CMAKE_BUILD_TYPE}")
message(STATUS "Compiler:     ${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}")
message(STATUS "Install path: ${CMAKE_INSTALL_PREFIX}")
message(STATUS "")
