cmake_minimum_required(VERSION 3.10)
project(multi_algo_cryptotool VERSION 1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

if(WIN32 AND NOT OPENSSL_ROOT_DIR AND EXISTS "${CMAKE_SOURCE_DIR}/deps/include/openssl")
    set(OPENSSL_ROOT_DIR "${CMAKE_SOURCE_DIR}/deps")
endif()
find_package(OpenSSL REQUIRED)

if(MINGW)
    string(APPEND CMAKE_EXE_LINKER_FLAGS " -static-libgcc -static-libstdc++")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " -static-libgcc -static-libstdc++")
endif()

set(OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${OUTPUT_DIRECTORY}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY "${OUTPUT_DIRECTORY}")
foreach(configuration ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER "${configuration}" configuration_upper)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${configuration_upper} "${OUTPUT_DIRECTORY}")
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${configuration_upper} "${OUTPUT_DIRECTORY}")
endforeach()

function(enable_strict_warnings target)
    if(MSVC)
        target_compile_options(${target} PRIVATE /W4 /WX /permissive- /utf-8)
    else()
        target_compile_options(${target} PRIVATE
            -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wsign-conversion -Wold-style-cast
            -Wcast-qual -Wnon-virtual-dtor -Wnull-dereference -Werror)
    endif()
endfunction()

set(ALGORITHMS elgamal table vernam)
foreach(algorithm ${ALGORITHMS})
    add_library(${algorithm} SHARED plugins/${algorithm}/${algorithm}.cpp)
    target_include_directories(${algorithm} PRIVATE include plugins)
    target_link_libraries(${algorithm} PRIVATE OpenSSL::Crypto)
    set_target_properties(${algorithm} PROPERTIES CXX_VISIBILITY_PRESET hidden VISIBILITY_INLINES_HIDDEN ON)
    if(WIN32)
        set_target_properties(${algorithm} PROPERTIES PREFIX "")
    endif()
    enable_strict_warnings(${algorithm})
endforeach()

set(HOST_SOURCES src/platform.cpp src/plugin_loader.cpp)

add_executable(cryptotool
    src/main.cpp src/application.cpp src/command_line.cpp src/crypto_service.cpp src/byte_stream.cpp src/stream_io.cpp
    ${HOST_SOURCES})
target_include_directories(cryptotool PRIVATE include src)
target_link_libraries(cryptotool PRIVATE ${CMAKE_DL_LIBS})
if(WIN32)
    target_link_libraries(cryptotool PRIVATE shell32)
endif()
add_dependencies(cryptotool ${ALGORITHMS})
enable_strict_warnings(cryptotool)

add_executable(cryptotool_tests tests/plugin_tests.cpp ${HOST_SOURCES})
target_include_directories(cryptotool_tests PRIVATE include src)
target_link_libraries(cryptotool_tests PRIVATE ${CMAKE_DL_LIBS})
if(WIN32)
    target_link_libraries(cryptotool_tests PRIVATE shell32)
endif()
add_dependencies(cryptotool_tests ${ALGORITHMS})
enable_strict_warnings(cryptotool_tests)

if(WIN32 AND EXISTS "${CMAKE_SOURCE_DIR}/deps/bin/libcrypto-3-x64.dll")
    add_custom_command(TARGET cryptotool POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${CMAKE_SOURCE_DIR}/deps/bin/libcrypto-3-x64.dll" "${OUTPUT_DIRECTORY}")
endif()

enable_testing()
add_test(NAME plugin_tests COMMAND cryptotool_tests)
