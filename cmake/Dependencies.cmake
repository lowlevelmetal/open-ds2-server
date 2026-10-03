include(FetchContent)

# --- Asio (standalone, header-only) -------------------------------------------
# Prefer a system install; otherwise fetch a pinned release.
find_path(ASIO_INCLUDE_DIR NAMES asio.hpp)
if(NOT ASIO_INCLUDE_DIR)
    FetchContent_Declare(asio
        URL https://github.com/chriskohlhoff/asio/archive/refs/tags/asio-1-38-2.tar.gz
        URL_HASH SHA256=9f2648fa483e58a6bf848d970ee0ea650ca19ed7769dfa520ed4f7b8d27af1db
        DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
    FetchContent_MakeAvailable(asio)
    set(ASIO_INCLUDE_DIR "${asio_SOURCE_DIR}/include")
endif()

find_package(Threads REQUIRED)

add_library(asio INTERFACE)
add_library(asio::asio ALIAS asio)
target_include_directories(asio SYSTEM INTERFACE "${ASIO_INCLUDE_DIR}")
target_compile_definitions(asio INTERFACE ASIO_STANDALONE ASIO_NO_DEPRECATED)
target_link_libraries(asio INTERFACE Threads::Threads)
if(WIN32)
    target_compile_definitions(asio INTERFACE _WIN32_WINNT=0x0A00)
    target_link_libraries(asio INTERFACE ws2_32 mswsock)
endif()

# --- GoogleTest ---------------------------------------------------------------
if(OPENDS2_BUILD_TESTS)
    find_package(GTest CONFIG QUIET)
    if(NOT GTest_FOUND)
        FetchContent_Declare(googletest
            URL https://github.com/google/googletest/archive/refs/tags/v1.17.0.tar.gz
            URL_HASH SHA256=65fab701d9829d38cb77c14acdc431d2108bfdbf8979e40eb8ae567edf10b27c
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
    endif()
endif()
