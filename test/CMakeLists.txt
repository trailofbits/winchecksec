cmake_minimum_required(VERSION 3.10 FATAL_ERROR)

project(winchecksec_test)

file(
  GLOB_RECURSE WINCHECKSEC_TEST_SOURCES
  LIST_DIRECTORIES false
  *.h *.cpp
)

add_executable("${PROJECT_NAME}" ${WINCHECKSEC_TEST_SOURCES})
add_test(NAME "${PROJECT_NAME}" COMMAND "${PROJECT_NAME}")
target_link_libraries("${PROJECT_NAME}" PUBLIC winchecksec gtest)
target_compile_definitions(
  "${PROJECT_NAME}" PRIVATE WINCHECKSEC_TEST_ASSETS="${CMAKE_CURRENT_SOURCE_DIR}/assets"
)
