project(webster)

cmake_minimum_required(VERSION 3.10)

set(WEBSTER_MAJOR_VERSION 3)
set(WEBSTER_MINOR_VERSION 0)
set(WEBSTER_PATCH_VERSION 0)

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
    set(ENABLE_PROFILING OFF CACHE BOOL "")
    set(ENABLE_SANITIZER OFF CACHE BOOL "")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -Wfatal-errors -fvisibility=hidden -pedantic -Wl,--no-undefined -fPIC -Wall -Wextra -Wconversion -Werror=return-type")

    if (ENABLE_PROFILING)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg")
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -g -O3")
    else()
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s -O3")
    endif()

    set(CMAKE_CXX_FLAGS_DEBUG     "${CMAKE_C_FLAGS_DEBUG} -g -O0")

    if (ENABLE_SANITIZER)
        set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -fsanitize=address")
        set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -fsanitize=address")
    endif()
endif()

add_library(libwebster STATIC
    "source/stream.cc"
    "source/http.cc"
    "source/http1.cc"
    "source/socket.cc"
    "source/network.cc")
target_compile_definitions(libwebster PRIVATE BUILDING_WEBSTER=1)
target_include_directories(libwebster PUBLIC "include")
set_target_properties(libwebster PROPERTIES
    OUTPUT_NAME "webster"
    VERSION "${WEBSTER_MAJOR_VERSION}.${WEBSTER_MINOR_VERSION}.${WEBSTER_PATCH_VERSION}"
    SOVERSION "${WEBSTER_MAJOR_VERSION}.${WEBSTER_MINOR_VERSION}.${WEBSTER_PATCH_VERSION}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    PREFIX "lib" )

add_executable(example_echo "examples/echo.cc")
target_link_libraries(example_echo libwebster)
target_compile_definitions(example_echo PRIVATE _DEFAULT_SOURCE)
set_target_properties(example_echo PROPERTIES
    OUTPUT_NAME "example_echo"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}" )

add_executable(example_client "examples/client.cc")
target_link_libraries(example_client libwebster)
target_compile_definitions(example_client PRIVATE _DEFAULT_SOURCE)
set_target_properties(example_client PROPERTIES
    OUTPUT_NAME "example_client"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}" )

if (UNIX)
    add_executable(example_indexing "examples/indexing.cc")
    target_link_libraries(example_indexing libwebster pthread)
    target_compile_definitions(example_indexing PRIVATE _DEFAULT_SOURCE)
    set_target_properties(example_indexing PROPERTIES
        OUTPUT_NAME "example_indexing"
        RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}" )
endif()

add_executable(generate_tool "generate.cc")
set_target_properties(generate_tool PROPERTIES
    OUTPUT_NAME "generate_tool"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}" )

set(WEBSTER_CC "${CMAKE_BINARY_DIR}/webster.cc")
set(FILE_LIST
    "${CMAKE_CURRENT_LIST_DIR}/source/stream.hh"
    "${CMAKE_CURRENT_LIST_DIR}/source/http.hh"
    "${CMAKE_CURRENT_LIST_DIR}/source/http1.hh"
    "${CMAKE_CURRENT_LIST_DIR}/source/socket.hh"
    "${CMAKE_CURRENT_LIST_DIR}/source/network.hh"
    "${CMAKE_CURRENT_LIST_DIR}/source/stream.cc"
    "${CMAKE_CURRENT_LIST_DIR}/source/http.cc"
    "${CMAKE_CURRENT_LIST_DIR}/source/http1.cc"
    "${CMAKE_CURRENT_LIST_DIR}/source/socket.cc"
    "${CMAKE_CURRENT_LIST_DIR}/source/network.cc")

add_custom_target(generate
    COMMAND "./generate_tool" ${WEBSTER_CC} ${FILE_LIST}
    DEPENDS libwebster generate_tool)

file(APPEND ${WEBSTER_CC} "")

add_library(libwebster_generated STATIC ${WEBSTER_CC})
target_compile_definitions(libwebster_generated PRIVATE BUILDING_WEBSTER=1 WEBSTER_AMALGAMATION=1)
target_include_directories(libwebster_generated PUBLIC "include")
add_dependencies(libwebster_generated generate)
set_target_properties(libwebster_generated PROPERTIES
    OUTPUT_NAME "webster_generated"
    VERSION "${WEBSTER_MAJOR_VERSION}.${WEBSTER_MINOR_VERSION}.${WEBSTER_PATCH_VERSION}"
    SOVERSION "${WEBSTER_MAJOR_VERSION}.${WEBSTER_MINOR_VERSION}.${WEBSTER_PATCH_VERSION}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    PREFIX "lib" )