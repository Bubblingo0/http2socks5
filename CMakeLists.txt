cmake_minimum_required(VERSION 3.0.0)
project(http2socks5)
if(NOT MSVC)
    add_definitions(-Wall -Wextra)
endif()

add_executable(http2socks5 test.cpp http2socks5.hpp)

find_package(Threads REQUIRED)
target_link_libraries(http2socks5 ${CMAKE_THREAD_LIBS_INIT})

find_package(Boost 1.66.0 REQUIRED)
include_directories(${Boost_INCLUDE_DIR})
#target_link_libraries(http2socks5 ${Boost_LIBRARIES})