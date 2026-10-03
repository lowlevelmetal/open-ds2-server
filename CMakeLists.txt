cmake_minimum_required(VERSION 3.25)

project(opends2server
    VERSION 0.1.0
    DESCRIPTION "Open-source server emulator for Dead Space 2 multiplayer"
    LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

option(OPENDS2_BUILD_TESTS "Build unit tests" ${PROJECT_IS_TOP_LEVEL})
option(OPENDS2_BUILD_TOOLS "Build reverse-engineering helper tools" ON)
option(OPENDS2_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake")
include(CompilerWarnings)
include(Dependencies)

add_subdirectory(src)

if(OPENDS2_BUILD_TOOLS)
    add_subdirectory(tools)
endif()

if(OPENDS2_BUILD_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
