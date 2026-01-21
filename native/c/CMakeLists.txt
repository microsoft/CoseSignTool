# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.20)

project(cose_sign1_c
    VERSION 0.1.0
    DESCRIPTION "C projection for COSE Sign1 validation"
    LANGUAGES C CXX
)

# Standard CMake testing option (BUILD_TESTING) + CTest integration.
include(CTest)

# C standard
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

# C++ is only used for optional GoogleTest-based tests (C API is still C).
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(COSE_ENABLE_ASAN "Enable AddressSanitizer for native builds" OFF)

if(COSE_ENABLE_ASAN)
    if(MSVC)
        add_compile_options(/fsanitize=address)
        if(CMAKE_VERSION VERSION_LESS "3.21")
            message(WARNING "COSE_ENABLE_ASAN is ON. On Windows, CMake 3.21+ is recommended so post-build steps can copy runtime DLL dependencies.")
        endif()
    elseif(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU" OR CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
endif()

# Find Rust FFI libraries
# These should be built first with: cargo build --release --workspace
set(RUST_FFI_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../rust/target/release")

# Base FFI library (required)
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

# Create interface library for headers
add_library(cose_headers INTERFACE)
target_include_directories(cose_headers INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Main library - just provides the Rust FFI libraries as an importable target
add_library(cose_sign1 INTERFACE)
target_link_libraries(cose_sign1 INTERFACE
    cose_headers
    ${COSE_FFI_BASE_LIB}
)

# Link standard system libraries required by Rust
if(WIN32)
    target_link_libraries(cose_sign1 INTERFACE
        ws2_32
        advapi32
        userenv
        bcrypt
        ntdll
    )
elseif(UNIX)
    target_link_libraries(cose_sign1 INTERFACE
        pthread
        dl
        m
    )
endif()

# Optional pack libraries
if(COSE_FFI_CERTIFICATES_LIB)
    message(STATUS "Found certificates pack: ${COSE_FFI_CERTIFICATES_LIB}")
    target_link_libraries(cose_sign1 INTERFACE ${COSE_FFI_CERTIFICATES_LIB})
    target_compile_definitions(cose_sign1 INTERFACE COSE_HAS_CERTIFICATES_PACK)
endif()

if(COSE_FFI_MST_LIB)
    message(STATUS "Found MST pack: ${COSE_FFI_MST_LIB}")
    target_link_libraries(cose_sign1 INTERFACE ${COSE_FFI_MST_LIB})
    target_compile_definitions(cose_sign1 INTERFACE COSE_HAS_MST_PACK)
endif()

if(COSE_FFI_AKV_LIB)
    message(STATUS "Found AKV pack: ${COSE_FFI_AKV_LIB}")
    target_link_libraries(cose_sign1 INTERFACE ${COSE_FFI_AKV_LIB})
    target_compile_definitions(cose_sign1 INTERFACE COSE_HAS_AKV_PACK)
endif()

if(COSE_FFI_TRUST_LIB)
    message(STATUS "Found trust pack: ${COSE_FFI_TRUST_LIB}")
    target_link_libraries(cose_sign1 INTERFACE ${COSE_FFI_TRUST_LIB})
    target_compile_definitions(cose_sign1 INTERFACE COSE_HAS_TRUST_PACK)
endif()

# Enable testing
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

add_subdirectory(examples)

# Installation rules
install(DIRECTORY include/cose
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

install(TARGETS cose_sign1 cose_headers
    EXPORT cose_sign1_targets
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib
    RUNTIME DESTINATION bin
    INCLUDES DESTINATION include
)

install(EXPORT cose_sign1_targets
    FILE cose_sign1-targets.cmake
    NAMESPACE cose::
    DESTINATION lib/cmake/cose_sign1
)
