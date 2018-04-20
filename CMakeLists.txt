project(webster)

cmake_minimum_required(VERSION 2.8)

set(WEBSTER_MAJOR_VERSION 1)
set(WEBSTER_MINOR_VERSION 0)
set(WEBSTER_PATCH_VERSION 0)


set(CMAKE_BUILD_TYPE "Release"  CACHE STRING  "Specify the build type")
set_property(CACHE  CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release")


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
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -Wfatal-errors -fvisibility=hidden -Wfatal-errors -pedantic -std=gnu99 -Wl,--no-undefined -fPIC -Wall -Wextra -Wconversion -Werror=return-type -Werror=implicit-function-declaration")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wfatal-errors -fvisibility=hidden -Wfatal-errors -pedantic -std=c++11 -Wl,--no-undefined -fPIC -Wall -Wextra -Wconversion -Werror=return-type -Werror=implicit-function-declaration")

    set(CMAKE_C_FLAGS_RELEASE  "${CMAKE_C_FLAGS_RELEASE} -s -O3")
    set(CMAKE_CXX_FLAGS_RELEASE  "${CMAKE_CXX_FLAGS_RELEASE} -s -O3")

    set(CMAKE_C_FLAGS_DEBUG  "${CMAKE_C_FLAGS_DEBUG} -g -O0")
    set(CMAKE_CXX_FLAGS_DEBUG  "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")

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


find_package(Threads REQUIRED)

add_definitions(-DBUILDING_WEBSTER=1)
include_directories("${CMAKE_CURRENT_LIST_DIR}/include")
add_library(libwebster SHARED
    "${CMAKE_CURRENT_LIST_DIR}/library/http.c"
    "${CMAKE_CURRENT_LIST_DIR}/library/interface.c")
target_link_libraries(libwebster ${CMAKE_THREAD_LIBS_INIT})
set_target_properties(libwebster PROPERTIES
    OUTPUT_NAME "webster"
    VERSION "${WEBSTERMAJOR_VERSION}.${WEBSTERMINOR_VERSION}.${WEBSTERPATCH_VERSION}"
    SOVERSION "${WEBSTERMAJOR_VERSION}.${WEBSTERMINOR_VERSION}.${WEBSTERPATCH_VERSION}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    PREFIX "lib" )


add_executable(webster "${CMAKE_CURRENT_LIST_DIR}/bin/main.c")
target_link_libraries(webster libwebster)
set_target_properties(webster PROPERTIES
    OUTPUT_NAME "webster"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}" )