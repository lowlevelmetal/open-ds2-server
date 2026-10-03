add_executable(tdfdump tdfdump.cpp)
target_link_libraries(tdfdump PRIVATE opends2_core)
opends2_set_warnings(tdfdump)
