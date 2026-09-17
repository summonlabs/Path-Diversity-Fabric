# Path Diversity Fabric 1.0.0 - Summon Software Labs.
# Apache License 2.0. See LICENSE.
cmake_minimum_required(VERSION 3.25)

project(PathDiversityFabric
  VERSION 1.0.0
  DESCRIPTION "Authoritative path-independence and diversity-proof runtime for the Distributed Fabric Infrastructure / Fabric OS stack"
  HOMEPAGE_URL "https://github.com/summonlabs/Path-Diversity-Fabric"
  LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_CXX_VISIBILITY_PRESET hidden)
set(CMAKE_VISIBILITY_INLINES_HIDDEN ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

option(PATH_DIVERSITY_BUILD_TESTS "Build the Path Diversity Fabric test suites" ON)
option(PATH_DIVERSITY_BUILD_EXAMPLES "Build the Path Diversity Fabric examples" ON)
option(PATH_DIVERSITY_BUILD_BENCHMARKS "Build the Path Diversity Fabric benchmarks" ON)
option(PATH_DIVERSITY_BUILD_CLI "Build the path_diversity command line tool" ON)
option(PATH_DIVERSITY_WARNINGS_AS_ERRORS "Treat first-party compiler warnings as errors" ON)
option(PATH_DIVERSITY_ENABLE_ASAN "Instrument first-party code with AddressSanitizer" OFF)
option(PATH_DIVERSITY_ENABLE_ANALYZE "Run MSVC static analysis on first-party code" OFF)

set(PATH_DIVERSITY_LIBRARY_TYPE "STATIC" CACHE STRING "Library type: STATIC or SHARED")
set_property(CACHE PATH_DIVERSITY_LIBRARY_TYPE PROPERTY STRINGS STATIC SHARED)

if(MSVC)
  add_library(path_diversity_project_options INTERFACE)
  target_compile_options(path_diversity_project_options INTERFACE
    /W4 /permissive- /utf-8 /Zc:__cplusplus /EHsc /MP)
  if(PATH_DIVERSITY_WARNINGS_AS_ERRORS)
    target_compile_options(path_diversity_project_options INTERFACE /WX)
  endif()
  if(PATH_DIVERSITY_ENABLE_ASAN)
    target_compile_options(path_diversity_project_options INTERFACE /fsanitize=address /Zi)
    target_link_options(path_diversity_project_options INTERFACE /INCREMENTAL:NO /DEBUG)
  endif()
  if(PATH_DIVERSITY_ENABLE_ANALYZE)
    target_compile_options(path_diversity_project_options INTERFACE /analyze /wd6011)
  endif()
  target_compile_definitions(path_diversity_project_options INTERFACE
    _CRT_SECURE_NO_WARNINGS NOMINMAX WIN32_LEAN_AND_MEAN)
else()
  add_library(path_diversity_project_options INTERFACE)
  target_compile_options(path_diversity_project_options INTERFACE
    -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion)
  if(PATH_DIVERSITY_WARNINGS_AS_ERRORS)
    target_compile_options(path_diversity_project_options INTERFACE -Werror)
  endif()
  if(PATH_DIVERSITY_ENABLE_ASAN)
    target_compile_options(path_diversity_project_options INTERFACE
      -fsanitize=address -fno-omit-frame-pointer)
    target_link_options(path_diversity_project_options INTERFACE -fsanitize=address)
  endif()
endif()

set(PATH_DIVERSITY_SOURCES
  src/authority.cpp
  src/canonical.cpp
  src/digest.cpp
  src/distributed.cpp
  src/domain.cpp
  src/evaluate_graph.cpp
  src/evaluate_pair.cpp
  src/evaluate_set.cpp
  src/evidence.cpp
  src/explain.cpp
  src/lifecycle.cpp
  src/limits.cpp
  src/mutation.cpp
  src/pathset.cpp
  src/persistence_records.cpp
  src/persistence_store.cpp
  src/policy.cpp
  src/proof.cpp
  src/runtime.cpp
  src/runtime_ops.cpp
  src/runtime_store.cpp
  src/runtime_view.cpp
  src/snapshot.cpp
  src/synthetic.cpp
  src/wire.cpp)

add_library(PathDiversityFabric ${PATH_DIVERSITY_LIBRARY_TYPE} ${PATH_DIVERSITY_SOURCES})
add_library(SummonSoftwareLabs::PathDiversityFabric ALIAS PathDiversityFabric)

target_include_directories(PathDiversityFabric PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)
# The internal evaluation helper header lives in src/ and must never leak into
# the installed interface.
target_include_directories(PathDiversityFabric PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/src)

target_compile_features(PathDiversityFabric PUBLIC cxx_std_20)
target_link_libraries(PathDiversityFabric PRIVATE
  $<BUILD_INTERFACE:path_diversity_project_options>)

set_target_properties(PathDiversityFabric PROPERTIES
  OUTPUT_NAME PathDiversityFabric
  VERSION ${PROJECT_VERSION}
  SOVERSION ${PROJECT_VERSION_MAJOR}
  DEFINE_SYMBOL path_diversity_EXPORTS)

if(WIN32)
  target_link_libraries(PathDiversityFabric PUBLIC ws2_32)
endif()

if(PATH_DIVERSITY_LIBRARY_TYPE STREQUAL "SHARED")
  target_compile_definitions(PathDiversityFabric PUBLIC PATH_DIVERSITY_SHARED)
endif()

if(PATH_DIVERSITY_BUILD_CLI)
  add_executable(path_diversity tools/path_diversity_cli.cpp)
  target_link_libraries(path_diversity PRIVATE PathDiversityFabric path_diversity_project_options)
  set_target_properties(path_diversity PROPERTIES OUTPUT_NAME path_diversity)
endif()

if(PATH_DIVERSITY_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(PATH_DIVERSITY_BUILD_BENCHMARKS)
  add_executable(path_diversity_benchmarks benchmarks/path_diversity_benchmarks.cpp)
  target_link_libraries(path_diversity_benchmarks PRIVATE
    PathDiversityFabric path_diversity_project_options)
  target_compile_definitions(path_diversity_benchmarks PRIVATE
    PATH_DIVERSITY_BENCHMARK_TEMP_ROOT="${CMAKE_CURRENT_BINARY_DIR}/benchmark-tmp")
endif()

if(PATH_DIVERSITY_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

install(TARGETS PathDiversityFabric
  EXPORT PathDiversityFabricTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

if(PATH_DIVERSITY_BUILD_CLI)
  install(TARGETS path_diversity RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
endif()

install(EXPORT PathDiversityFabricTargets
  FILE PathDiversityFabricTargets.cmake
  NAMESPACE SummonSoftwareLabs::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PathDiversityFabric)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/PathDiversityFabricConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/PathDiversityFabricConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PathDiversityFabric)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/PathDiversityFabricConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/PathDiversityFabricConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/PathDiversityFabricConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/PathDiversityFabric)
