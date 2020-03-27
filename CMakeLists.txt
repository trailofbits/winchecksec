project(winchecksec)

cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

add_subdirectory(pe-parse)
include_directories(pe-parse/pe-parser-library/include)
link_directories(build/pe-parse/pe-parser-library/${CMAKE_BUILD_TYPE})

add_library(winchecksec SHARED Checksec.cc Checksec.h)
target_compile_definitions(winchecksec PRIVATE _WINCHECKSEC_EXPORT=1)
if (MSVC)
    target_link_libraries(winchecksec wintrust pe-parser-library)
else ()
    target_link_libraries(winchecksec pe-parser-library)
endif ()

# Dumb hack to build an executable with the same name.
add_executable(winchecksec-bin Checksec.cc main.cc)
target_compile_definitions(winchecksec-bin PRIVATE _WINCHECKSEC_STANDALONE=1)
if (MSVC)
    target_link_libraries(winchecksec-bin wintrust pe-parser-library)
else ()
    target_link_libraries(winchecksec-bin pe-parser-library)
endif ()

set_target_properties(winchecksec-bin PROPERTIES OUTPUT_NAME winchecksec)
