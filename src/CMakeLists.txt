# Everything except main() lives in a static library so tests and tools can link it.
add_library(opends2_core STATIC
    core/config.cpp
    core/hexdump.cpp
    core/log.cpp
    blaze/frame.cpp
    blaze/router.cpp
    blaze/tdf.cpp
    net/session.cpp
    server/server.cpp
    services/redirector.cpp
    services/util.cpp)

target_include_directories(opends2_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(opends2_core PUBLIC asio::asio)
opends2_set_warnings(opends2_core)

add_executable(opends2server main.cpp)
target_link_libraries(opends2server PRIVATE opends2_core)
opends2_set_warnings(opends2server)
