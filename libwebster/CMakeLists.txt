
set(SOURCES
    "source/internal.cc"
    "source/network.cc"
    "source/http.cc"
    "source/api.cc")

add_library(libwebster SHARED ${SOURCES})
target_compile_definitions(libwebster PRIVATE BUILDING_WEBSTER=1)
target_include_directories(libwebster
    PUBLIC "include")
target_compile_definitions(libwebster
    PRIVATE BUILDING_DYNAMIC=1)
set_target_properties(libwebster PROPERTIES
    OUTPUT_NAME "webster"
    VERSION "${WEBSTER_MAJOR_VERSION}.${WEBSTER_MINOR_VERSION}.${WEBSTER_PATCH_VERSION}"
    SOVERSION "${WEBSTER_MAJOR_VERSION}.${WEBSTER_MINOR_VERSION}.${WEBSTER_PATCH_VERSION}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    PREFIX "lib" )


add_library(libwebster_static STATIC ${SOURCES})
target_compile_definitions(libwebster_static PRIVATE BUILDING_WEBSTER=1)
target_include_directories(libwebster_static
    PUBLIC "include")
set_target_properties(libwebster_static PROPERTIES
    OUTPUT_NAME "webster"
    VERSION "${WEBSTER_MAJOR_VERSION}.${WEBSTER_MINOR_VERSION}.${WEBSTER_PATCH_VERSION}"
    SOVERSION "${WEBSTER_MAJOR_VERSION}.${WEBSTER_MINOR_VERSION}.${WEBSTER_PATCH_VERSION}"
    ARCHIVE_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}"
    PREFIX "lib" )