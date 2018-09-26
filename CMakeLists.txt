if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "Winchecksec should be built as a 64-bit binary.")
endif(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)

add_executable(winchecksec main.cpp Checksec.cpp)

target_link_libraries(winchecksec wintrust)
target_link_libraries(winchecksec imagehlp)
