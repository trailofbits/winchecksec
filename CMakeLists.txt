add_executable(winchecksec main.cc Checksec.cc)

target_link_libraries(winchecksec wintrust)
