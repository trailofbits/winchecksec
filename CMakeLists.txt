add_executable(winchecksec main.cpp Checksec.cpp)

target_link_libraries(winchecksec wintrust)
target_link_libraries(winchecksec imagehlp)
