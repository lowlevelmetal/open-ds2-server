cmake_minimum_required(VERSION 3.16)
project(open-ds2-server 
    VERSION 0.1.0
    DESCRIPTION "Open source Dead Space 2 server emulator"
    LANGUAGES CXX C
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

# Option to use bundled OpenSSL 1.1.1 (required for legacy game support)
option(USE_BUNDLED_OPENSSL "Build with bundled OpenSSL 1.1.1 for legacy TLS support" ON)

if(USE_BUNDLED_OPENSSL)
    include(ExternalProject)
    
    set(OPENSSL_VERSION "1.1.1w")
    set(OPENSSL_INSTALL_DIR ${CMAKE_BINARY_DIR}/openssl-install)
    
    ExternalProject_Add(openssl_external
        URL https://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz
        URL_HASH SHA256=cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        CONFIGURE_COMMAND <SOURCE_DIR>/config 
            --prefix=${OPENSSL_INSTALL_DIR}
            --openssldir=${OPENSSL_INSTALL_DIR}
            no-shared
            enable-ssl3
            enable-ssl3-method
            enable-weak-ssl-ciphers
        BUILD_COMMAND make -j4
        INSTALL_COMMAND make install_sw
        BUILD_IN_SOURCE 1
    )
    
    # Create directory structure so CMake doesn't complain
    file(MAKE_DIRECTORY ${OPENSSL_INSTALL_DIR}/include)
    file(MAKE_DIRECTORY ${OPENSSL_INSTALL_DIR}/lib)
    
    # Set OpenSSL paths for our build
    set(OPENSSL_INCLUDE_DIR ${OPENSSL_INSTALL_DIR}/include)
    set(OPENSSL_SSL_LIBRARY ${OPENSSL_INSTALL_DIR}/lib/libssl.a)
    set(OPENSSL_CRYPTO_LIBRARY ${OPENSSL_INSTALL_DIR}/lib/libcrypto.a)
    
    message(STATUS "Using bundled OpenSSL ${OPENSSL_VERSION} with legacy SSL support")
else()
    find_package(OpenSSL REQUIRED)
    message(STATUS "Using system OpenSSL ${OPENSSL_VERSION}")
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/src)
if(USE_BUNDLED_OPENSSL)
    include_directories(SYSTEM ${OPENSSL_INCLUDE_DIR})
endif()

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

# Link libraries
if(USE_BUNDLED_OPENSSL)
    add_dependencies(ds2-server openssl_external)
    target_link_libraries(ds2-server PRIVATE
        Threads::Threads
        ${OPENSSL_SSL_LIBRARY}
        ${OPENSSL_CRYPTO_LIBRARY}
        ${CMAKE_DL_LIBS}
    )
else()
    target_link_libraries(ds2-server PRIVATE
        Threads::Threads
        OpenSSL::SSL
        OpenSSL::Crypto
    )
endif()

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
