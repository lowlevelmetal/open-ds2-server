add_executable(opends2_tests
    config_test.cpp
    frame_test.cpp
    tdf_test.cpp)

target_link_libraries(opends2_tests PRIVATE opends2_core GTest::gtest_main)
opends2_set_warnings(opends2_tests)

include(GoogleTest)
gtest_discover_tests(opends2_tests)
