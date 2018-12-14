cmake_minimum_required(VERSION 3.12 FATAL_ERROR)

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Winchecksec should be built as a 64-bit binary.")
endif(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)

add_library(winchecksec SHARED Checksec.cpp)
target_link_libraries(winchecksec wintrust)
target_link_libraries(winchecksec imagehlp)

# Dumb hack to build an executable with the same name.
add_executable(winchecksec-bin main.cpp Checksec.cpp)
target_link_libraries(winchecksec-bin wintrust)
target_link_libraries(winchecksec-bin imagehlp)
set_target_properties(winchecksec-bin PROPERTIES OUTPUT_NAME winchecksec)
