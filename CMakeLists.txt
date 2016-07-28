cmake_minimum_required(VERSION 3.5)
project(ePass2003_test)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

set(SOURCE_FILES pam_test.c pam_test.h test.c )
add_executable(ePass2003_test ${SOURCE_FILES})