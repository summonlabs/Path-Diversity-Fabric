# Path Diversity Fabric 1.0.0 - Summon Software Labs.
# Apache License 2.0. See LICENSE.

# Independent consumer of the installed package. This project is deliberately
# not part of the library build: it resolves the package by config mode only, so
# an incomplete install or export surface fails here rather than inside the
# project that produced it.
#
#   cmake --install <library-build> --prefix <prefix>
#   cmake -S tests/consumer -B <consumer-build> -G Ninja -DCMAKE_PREFIX_PATH=<prefix>
#   cmake --build <consumer-build>

cmake_minimum_required(VERSION 3.25)

project(PathDiversityFabricConsumer VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(PathDiversityFabric CONFIG REQUIRED)

add_executable(app main.cpp)
target_link_libraries(app PRIVATE SummonSoftwareLabs::PathDiversityFabric)

if(MSVC)
  target_compile_options(app PRIVATE /W4 /permissive- /utf-8 /Zc:__cplusplus /WX)
else()
  target_compile_options(app PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
