project(webster)

cmake_minimum_required(VERSION 2.8)

set(WEBSTER_MAJOR_VERSION 1)
set(WEBSTER_MINOR_VERSION 0)
set(WEBSTER_PATCH_VERSION 0)

set(LIBRARY_TYPE "SHARED" CACHE STRING "Specify the type of binary to be generated")
set_property(CACHE LIBRARY_TYPE PROPERTY STRINGS "STATIC" "SHARED")

set(CMAKE_BUILD_TYPE "Release"  CACHE STRING  "Specify the build type")
set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")


if (UNIX)
    set(CMAKE_BUILD_PLATFORM "auto"  CACHE STRING  "Target platform which the binaries will be generated")
    set_property(CACHE CMAKE_BUILD_PLATFORM PROPERTY STRINGS "auto" "x86_64" "x86")

    if (NOT CMAKE_BUILD_PLATFORM STREQUAL "auto" AND
        NOT CMAKE_BUILD_PLATFORM STREQUAL "x86" AND
        NOT CMAKE_BUILD_PLATFORM STREQUAL "x86_64")
        set(CMAKE_BUILD_PLATFORM "auto")
    endif()
endif()

if (NOT CMAKE_BUILD_PLATFORM OR "${CMAKE_BUILD_PLATFORM}" STREQUAL "auto")
    if (${CMAKE_SIZEOF_VOID_P} EQUAL 4)
        set(CMAKE_BUILD_PLATFORM "x86")
    elseif(${CMAKE_SIZEOF_VOID_P} EQUAL 8)
        set(CMAKE_BUILD_PLATFORM "x86_64")
    endif()
endif()


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
    set(COMMON_FLAGS "-Wfatal-errors -fvisibility=hidden -Wfatal-errors -pedantic -Wl,--no-undefined -fPIC -Wall -Wextra -Wconversion -Werror=int-conversion -Werror=return-type -Werror=implicit-function-declaration -Werror=incompatible-pointer-types -Werror=discarded-qualifiers")

    set(CMAKE_C_FLAGS           "${CMAKE_C_FLAGS} -std=c99 ${COMMON_FLAGS}")
    set(CMAKE_C_FLAGS_RELEASE   "${CMAKE_C_FLAGS_RELEASE} -s -O3")
    set(CMAKE_C_FLAGS_DEBUG     "${CMAKE_C_FLAGS_DEBUG} -g -O0")

    set(CMAKE_CXX_FLAGS         "${CMAKE_CXX_FLAGS} -std=c++98  ${COMMON_FLAGS}")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -s -O3")
    set(CMAKE_CXX_FLAGS_DEBUG   "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")

    if(CMAKE_BUILD_PLATFORM STREQUAL "x86")
        set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m32" )
        set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m32" )
        set( CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m32" )
        set( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m32" )
    elseif(CMAKE_BUILD_PLATFORM STREQUAL "x86_64")
        set( CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -m64" )
        set( CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -m64" )
        set( CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -m64" )
        set( CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -m64" )
    endif()
endif()


add_library(libwebster SHARED "webster.c")
target_compile_definitions(libwebster PRIVATE BUILDING_WEBSTER=1)
target_include_directories(libwebster PUBLIC "./")
target_compile_definitions(libwebster PRIVATE BUILDING_DYNAMIC=1)
set_target_properties(libwebster PROPERTIES
    OUTPUT_NAME "webster"
    VERSION "${WEBSTER_MAJOR_VERSION}.${WEBSTER_MINOR_VERSION}.${WEBSTER_PATCH_VERSION}"
    SOVERSION "${WEBSTER_MAJOR_VERSION}.${WEBSTER_MINOR_VERSION}.${WEBSTER_PATCH_VERSION}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    PREFIX "lib" )


add_library(libwebster_static STATIC "webster.c")
target_compile_definitions(libwebster_static PRIVATE BUILDING_WEBSTER=1)
target_include_directories(libwebster_static PUBLIC "./")
set_target_properties(libwebster_static PROPERTIES
    OUTPUT_NAME "webster"
    VERSION "${WEBSTER_MAJOR_VERSION}.${WEBSTER_MINOR_VERSION}.${WEBSTER_PATCH_VERSION}"
    SOVERSION "${WEBSTER_MAJOR_VERSION}.${WEBSTER_MINOR_VERSION}.${WEBSTER_PATCH_VERSION}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    PREFIX "lib" )


find_package(Threads REQUIRED)

add_executable(example_echo "examples/echo.c")
target_link_libraries(example_echo libwebster_static)
target_compile_definitions(example_echo PRIVATE _DEFAULT_SOURCE)
set_target_properties(example_echo PROPERTIES
    OUTPUT_NAME "example_echo"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}" )


add_executable(example_client "examples/client.c")
target_link_libraries(example_client libwebster_static)
target_compile_definitions(example_client PRIVATE _DEFAULT_SOURCE)
set_target_properties(example_client PROPERTIES
    OUTPUT_NAME "example_client"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}" )


add_executable(example_indexing "examples/indexing.c")
target_link_libraries(example_indexing libwebster)
target_compile_definitions(example_indexing PRIVATE _DEFAULT_SOURCE)
set_target_properties(example_indexing PROPERTIES
    OUTPUT_NAME "example_indexing"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}" )
