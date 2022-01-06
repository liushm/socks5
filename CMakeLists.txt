if (MSVC)
    set(CMAKE_TOOLCHAIN_FILE "C:/Users/A/software/vcpkg/scripts/buildsystems/vcpkg.cmake")
	set(VCPKG_TARGET_TRIPLET "x64-windows")
endif (MSVC)

cmake_minimum_required(VERSION 3.10)
project(test)

find_package(Boost REQUIRED)

include_directories(${Boost_INCLUDE_DIRS})

add_executable(test main.cc)
target_compile_features(test PRIVATE cxx_std_17)
if (MSVC)
    target_compile_options(test PUBLIC "/utf-8")
elseif (UNIX)
    target_link_libraries(test pthread)
endif ()
