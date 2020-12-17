project(webster)

cmake_minimum_required(VERSION 2.8)

set(WEBSTER_MAJOR_VERSION 2)
set(WEBSTER_MINOR_VERSION 0)
set(WEBSTER_PATCH_VERSION 1)

set(LIBRARY_TYPE "SHARED" CACHE STRING "Specify the type of binary to be generated")
set_property(CACHE LIBRARY_TYPE PROPERTY STRINGS "STATIC" "SHARED")

if (CMAKE_BUILD_TYPE STREQUAL "")
    message(STATUS "No build type selected, default to 'Release'")
    set(CMAKE_BUILD_TYPE "Release")
endif()

if (CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(WEBSTER_BUILD_DEBUG 1)
else()
    set(WEBSTER_BUILD_RELEASE 1)
endif()

if(MSVC)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -DNOMINMAX -DWIN32_LEAN_AND_MEAN)
endif()

if (UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wfatal-errors -fvisibility=hidden -Wfatal-errors -pedantic -Wl,--no-undefined -fPIC -Wall -Wextra -Wconversion -Werror=return-type")
    set(CMAKE_CXX_FLAGS_RELEASE   "${CMAKE_C_FLAGS_RELEASE} -s -O3")
    set(CMAKE_CXX_FLAGS_DEBUG     "${CMAKE_C_FLAGS_DEBUG} -g -O0")
endif()

add_library(libwebster STATIC "webster.cc")
target_compile_definitions(libwebster PRIVATE BUILDING_WEBSTER=1)
target_include_directories(libwebster PUBLIC ".")
set_target_properties(libwebster PROPERTIES
    OUTPUT_NAME "webster"
    VERSION "${WEBSTER_MAJOR_VERSION}.${WEBSTER_MINOR_VERSION}.${WEBSTER_PATCH_VERSION}"
    SOVERSION "${WEBSTER_MAJOR_VERSION}.${WEBSTER_MINOR_VERSION}.${WEBSTER_PATCH_VERSION}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    PREFIX "lib" )


#find_package(Threads REQUIRED)

add_executable(example_echo "examples/echo.cc")
target_link_libraries(example_echo libwebster)
target_compile_definitions(example_echo PRIVATE _DEFAULT_SOURCE)
set_target_properties(example_echo PROPERTIES
    OUTPUT_NAME "example_echo"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}" )


add_executable(example_client "examples/client.cc")
target_link_libraries(example_client libwebster)
target_compile_definitions(example_client PRIVATE _DEFAULT_SOURCE)
set_target_properties(example_client PROPERTIES
    OUTPUT_NAME "example_client"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}" )


add_executable(example_indexing "examples/indexing.cc")
if (UNIX)
    target_link_libraries(example_indexing libwebster pthread)
else()
    target_link_libraries(example_indexing libwebster)
endif()
target_compile_definitions(example_indexing PRIVATE _DEFAULT_SOURCE)
set_target_properties(example_indexing PROPERTIES
    OUTPUT_NAME "example_indexing"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}" )
