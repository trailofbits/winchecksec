project(winchecksec)

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

find_package(pe-parse REQUIRED)
find_package(uthenticode REQUIRED)

# TODO(ww): Remove this when we bump to uthenticode 1.0.3.
find_package(OpenSSL 1.1 COMPONENTS Crypto REQUIRED)
if ("${CMAKE_BUILD_TYPE}" STREQUAL "Debug" OR "${CMAKE_BUILD_TYPE}" STREQUAL "RelWithDebInfo")
  if (NOT MSVC)
    add_link_options(-fsanitize=address)
  endif ()
endif ()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(winchecksec Checksec.cc Checksec.h)
target_compile_definitions(winchecksec PRIVATE _WINCHECKSEC_EXPORT=1)
target_link_libraries(winchecksec PRIVATE pe-parse::pe-parser-library uthenticode::uthenticode)

add_executable(winchecksec-bin Checksec.cc main.cc)
target_compile_definitions(winchecksec-bin PRIVATE _WINCHECKSEC_STANDALONE=1)
target_link_libraries(winchecksec-bin PRIVATE pe-parse::pe-parser-library uthenticode::uthenticode)

# Dumb hack to build an executable with the same name.
set_target_properties(winchecksec-bin PROPERTIES OUTPUT_NAME winchecksec)
