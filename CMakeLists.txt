cmake_minimum_required(VERSION 3.10)
project(test)

add_executable(test main.cc)
target_compile_features(test PRIVATE cxx_std_17)
target_include_directories(test PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/asio")
if (MSVC)
    target_compile_options(test PUBLIC "/utf-8")
endif (MSVC)
