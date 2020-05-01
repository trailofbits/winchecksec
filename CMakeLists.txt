project(winchecksec)

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

find_package(pe-parse REQUIRED)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(winchecksec Checksec.cc Checksec.h)
target_compile_definitions(winchecksec PRIVATE _WINCHECKSEC_EXPORT=1)
target_link_libraries(winchecksec PRIVATE pe-parse::pe-parser-library)
if (MSVC)
    target_sources(winchecksec PRIVATE authenticode.cc)
endif ()

# Dumb hack to build an executable with the same name.
add_executable(winchecksec-bin Checksec.cc main.cc)
target_compile_definitions(winchecksec-bin PRIVATE _WINCHECKSEC_STANDALONE=1)
target_link_libraries(winchecksec-bin PRIVATE pe-parse::pe-parser-library)
if (MSVC)
    target_sources(winchecksec-bin PRIVATE authenticode.cc)
    target_link_libraries(winchecksec-bin PRIVATE wintrust)
endif ()

set_target_properties(winchecksec-bin PROPERTIES OUTPUT_NAME winchecksec)
