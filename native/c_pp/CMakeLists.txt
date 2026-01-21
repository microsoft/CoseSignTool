# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.20)

project(cose_sign1_cpp
    VERSION 0.1.0
    DESCRIPTION "C++ projection for COSE Sign1 validation"
    LANGUAGES CXX
)

# Standard CMake testing option (BUILD_TESTING) + CTest integration.
include(CTest)

# C++ standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(COSE_ENABLE_ASAN "Enable AddressSanitizer for native builds" OFF)

if(COSE_ENABLE_ASAN)
    if(MSVC)
        add_compile_options(/fsanitize=address)
        if(CMAKE_VERSION VERSION_LESS "3.21")
            message(WARNING "COSE_ENABLE_ASAN is ON. On Windows, CMake 3.21+ is recommended so post-build steps can copy runtime DLL dependencies.")
        endif()
    elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
endif()

# Find the C projection (headers and libraries)
set(C_PROJECTION_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../c")
set(RUST_FFI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../rust/target/release")

# Find C headers
if(NOT EXISTS "${C_PROJECTION_DIR}/include")
    message(FATAL_ERROR "C projection headers not found at ${C_PROJECTION_DIR}/include")
endif()

# Find Rust FFI libraries
find_library(COSE_FFI_BASE_LIB
    NAMES cose_sign1_validation_ffi
    PATHS ${RUST_FFI_DIR}
    REQUIRED
)

# Pack FFI libraries (optional)
find_library(COSE_FFI_CERTIFICATES_LIB
    NAMES cose_sign1_validation_ffi_certificates
    PATHS ${RUST_FFI_DIR}
)

find_library(COSE_FFI_MST_LIB
    NAMES cose_sign1_validation_ffi_mst
    PATHS ${RUST_FFI_DIR}
)

find_library(COSE_FFI_AKV_LIB
    NAMES cose_sign1_validation_ffi_akv
    PATHS ${RUST_FFI_DIR}
)

find_library(COSE_FFI_TRUST_LIB
    NAMES cose_sign1_validation_ffi_trust
    PATHS ${RUST_FFI_DIR}
)

# Create interface library for C++ headers
add_library(cose_cpp_headers INTERFACE)
target_include_directories(cose_cpp_headers INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${C_PROJECTION_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Main C++ library - header-only wrappers around C API
add_library(cose_sign1_cpp INTERFACE)
target_link_libraries(cose_sign1_cpp INTERFACE
    cose_cpp_headers
    ${COSE_FFI_BASE_LIB}
)

# Link standard system libraries required by Rust
if(WIN32)
    target_link_libraries(cose_sign1_cpp INTERFACE
        ws2_32
        advapi32
        userenv
        bcrypt
        ntdll
    )
elseif(UNIX)
    target_link_libraries(cose_sign1_cpp INTERFACE
        pthread
        dl
        m
    )
endif()

# Optional pack libraries
if(COSE_FFI_CERTIFICATES_LIB)
    message(STATUS "Found certificates pack: ${COSE_FFI_CERTIFICATES_LIB}")
    target_link_libraries(cose_sign1_cpp INTERFACE ${COSE_FFI_CERTIFICATES_LIB})
    target_compile_definitions(cose_sign1_cpp INTERFACE COSE_HAS_CERTIFICATES_PACK)
endif()

if(COSE_FFI_MST_LIB)
    message(STATUS "Found MST pack: ${COSE_FFI_MST_LIB}")
    target_link_libraries(cose_sign1_cpp INTERFACE ${COSE_FFI_MST_LIB})
    target_compile_definitions(cose_sign1_cpp INTERFACE COSE_HAS_MST_PACK)
endif()

if(COSE_FFI_AKV_LIB)
    message(STATUS "Found AKV pack: ${COSE_FFI_AKV_LIB}")
    target_link_libraries(cose_sign1_cpp INTERFACE ${COSE_FFI_AKV_LIB})
    target_compile_definitions(cose_sign1_cpp INTERFACE COSE_HAS_AKV_PACK)
endif()

if(COSE_FFI_TRUST_LIB)
    message(STATUS "Found trust pack: ${COSE_FFI_TRUST_LIB}")
    target_link_libraries(cose_sign1_cpp INTERFACE ${COSE_FFI_TRUST_LIB})
    target_compile_definitions(cose_sign1_cpp INTERFACE COSE_HAS_TRUST_PACK)
endif()

# Enable testing
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

add_subdirectory(examples)

# Installation rules
install(DIRECTORY include/cose
    DESTINATION include
    FILES_MATCHING PATTERN "*.hpp"
)

install(TARGETS cose_sign1_cpp cose_cpp_headers
    EXPORT cose_sign1_cpp_targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(EXPORT cose_sign1_cpp_targets
    FILE cose_sign1_cpp-targets.cmake
    NAMESPACE cose::
    DESTINATION lib/cmake/cose_sign1_cpp
)
