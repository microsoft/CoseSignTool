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

# Provider selection options
set(COSE_CRYPTO_PROVIDER "openssl" CACHE STRING "Crypto provider (openssl|none)")
set_property(CACHE COSE_CRYPTO_PROVIDER PROPERTY STRINGS openssl none)

set(COSE_CBOR_PROVIDER "everparse" CACHE STRING "CBOR provider (everparse)")
set_property(CACHE COSE_CBOR_PROVIDER PROPERTY STRINGS everparse)

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
# Two-phase find: prefer local Rust build (NO_DEFAULT_PATH), then fall back to
# system/vcpkg paths. The Rust crate name and the vcpkg port name differ, so
# both are listed in NAMES.
find_library(COSE_FFI_CERTIFICATES_LIB
    NAMES cose_sign1_certificates_ffi cose_sign1_validation_ffi_certificates
    PATHS ${RUST_FFI_DIR}
    NO_DEFAULT_PATH
)
find_library(COSE_FFI_CERTIFICATES_LIB
    NAMES cose_sign1_certificates_ffi cose_sign1_validation_ffi_certificates
)

find_library(COSE_FFI_MST_LIB
    NAMES cose_sign1_transparent_mst_ffi cose_sign1_validation_ffi_mst
    PATHS ${RUST_FFI_DIR}
    NO_DEFAULT_PATH
)
find_library(COSE_FFI_MST_LIB
    NAMES cose_sign1_transparent_mst_ffi cose_sign1_validation_ffi_mst
)

find_library(COSE_FFI_AKV_LIB
    NAMES cose_sign1_azure_key_vault_ffi cose_sign1_validation_ffi_akv
    PATHS ${RUST_FFI_DIR}
    NO_DEFAULT_PATH
)
find_library(COSE_FFI_AKV_LIB
    NAMES cose_sign1_azure_key_vault_ffi cose_sign1_validation_ffi_akv
)

find_library(COSE_FFI_TRUST_LIB
    NAMES cose_sign1_validation_primitives_ffi
    PATHS ${RUST_FFI_DIR}
)

# Additional FFI libraries (optional)
find_library(COSE_FFI_PRIMITIVES_LIB
    NAMES cose_sign1_primitives_ffi
    PATHS ${RUST_FFI_DIR}
)

find_library(COSE_FFI_SIGNING_LIB
    NAMES cose_sign1_signing_ffi
    PATHS ${RUST_FFI_DIR}
)

find_library(COSE_FFI_HEADERS_LIB
    NAMES cose_sign1_headers_ffi
    PATHS ${RUST_FFI_DIR}
)

find_library(COSE_FFI_DID_X509_LIB
    NAMES did_x509_ffi
    PATHS ${RUST_FFI_DIR}
)

find_library(COSE_FFI_CERTIFICATES_LOCAL_LIB
    NAMES cose_sign1_certificates_local_ffi
    PATHS ${RUST_FFI_DIR}
)

find_library(COSE_FFI_CRYPTO_OPENSSL_LIB
    NAMES cose_sign1_crypto_openssl_ffi
    PATHS ${RUST_FFI_DIR}
)

find_library(COSE_FFI_FACTORIES_LIB
    NAMES cose_sign1_factories_ffi
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

# Additional optional FFI library targets
if(COSE_FFI_PRIMITIVES_LIB)
    message(STATUS "Found primitives FFI: ${COSE_FFI_PRIMITIVES_LIB}")
    add_library(cose_primitives INTERFACE)
    target_link_libraries(cose_primitives INTERFACE
        cose_headers
        ${COSE_FFI_PRIMITIVES_LIB}
    )
    target_compile_definitions(cose_primitives INTERFACE COSE_HAS_PRIMITIVES)
endif()

if(COSE_FFI_SIGNING_LIB)
    message(STATUS "Found signing FFI: ${COSE_FFI_SIGNING_LIB}")
    add_library(cose_signing INTERFACE)
    target_link_libraries(cose_signing INTERFACE
        cose_headers
        ${COSE_FFI_SIGNING_LIB}
    )
    target_compile_definitions(cose_signing INTERFACE COSE_HAS_SIGNING)
endif()

if(COSE_FFI_HEADERS_LIB)
    message(STATUS "Found CWT headers FFI: ${COSE_FFI_HEADERS_LIB}")
    add_library(cose_cwt_headers INTERFACE)
    target_link_libraries(cose_cwt_headers INTERFACE
        cose_headers
        ${COSE_FFI_HEADERS_LIB}
    )
    target_compile_definitions(cose_cwt_headers INTERFACE COSE_HAS_CWT_HEADERS)
endif()

if(COSE_FFI_DID_X509_LIB)
    message(STATUS "Found DID:x509 FFI: ${COSE_FFI_DID_X509_LIB}")
    add_library(cose_did_x509 INTERFACE)
    target_link_libraries(cose_did_x509 INTERFACE
        cose_headers
        ${COSE_FFI_DID_X509_LIB}
    )
    target_compile_definitions(cose_did_x509 INTERFACE COSE_HAS_DID_X509)
endif()

if(COSE_FFI_CERTIFICATES_LOCAL_LIB)
    message(STATUS "Found certificates local FFI: ${COSE_FFI_CERTIFICATES_LOCAL_LIB}")
    add_library(cose_certificates_local INTERFACE)
    target_link_libraries(cose_certificates_local INTERFACE
        cose_headers
        ${COSE_FFI_CERTIFICATES_LOCAL_LIB}
    )
    target_compile_definitions(cose_certificates_local INTERFACE COSE_HAS_CERTIFICATES_LOCAL)
endif()

if(COSE_FFI_CRYPTO_OPENSSL_LIB)
    message(STATUS "Found crypto OpenSSL FFI: ${COSE_FFI_CRYPTO_OPENSSL_LIB}")
    add_library(cose_crypto_openssl INTERFACE)
    target_link_libraries(cose_crypto_openssl INTERFACE
        cose_headers
        ${COSE_FFI_CRYPTO_OPENSSL_LIB}
    )
    target_compile_definitions(cose_crypto_openssl INTERFACE COSE_HAS_CRYPTO_OPENSSL)
endif()

if(COSE_FFI_FACTORIES_LIB)
    message(STATUS "Found factories FFI: ${COSE_FFI_FACTORIES_LIB}")
    add_library(cose_factories INTERFACE)
    target_link_libraries(cose_factories INTERFACE
        cose_headers
        ${COSE_FFI_FACTORIES_LIB}
    )
    target_compile_definitions(cose_factories INTERFACE COSE_HAS_FACTORIES)
endif()

# Set provider compile definitions
if(COSE_CRYPTO_PROVIDER STREQUAL "openssl")
    target_compile_definitions(cose_sign1 INTERFACE COSE_CRYPTO_OPENSSL)
    message(STATUS "COSE crypto provider: OpenSSL")
endif()

if(COSE_CBOR_PROVIDER STREQUAL "everparse")
    target_compile_definitions(cose_sign1 INTERFACE COSE_CBOR_EVERPARSE)
    message(STATUS "COSE CBOR provider: EverParse")
endif()

# Enable testing
if(BUILD_TESTING)
    add_subdirectory(tests)
endif()

option(BUILD_EXAMPLES "Build example programs" ON)
if(BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

# Installation rules
install(DIRECTORY include/cose
    DESTINATION include
    FILES_MATCHING PATTERN "*.h"
)

# Build list of targets to install dynamically
set(COSE_INSTALL_TARGETS cose_sign1 cose_headers)
if(COSE_FFI_PRIMITIVES_LIB)
    list(APPEND COSE_INSTALL_TARGETS cose_primitives)
endif()
if(COSE_FFI_SIGNING_LIB)
    list(APPEND COSE_INSTALL_TARGETS cose_signing)
endif()
if(COSE_FFI_HEADERS_LIB)
    list(APPEND COSE_INSTALL_TARGETS cose_cwt_headers)
endif()
if(COSE_FFI_DID_X509_LIB)
    list(APPEND COSE_INSTALL_TARGETS cose_did_x509)
endif()
if(COSE_FFI_CERTIFICATES_LOCAL_LIB)
    list(APPEND COSE_INSTALL_TARGETS cose_certificates_local)
endif()
if(COSE_FFI_CRYPTO_OPENSSL_LIB)
    list(APPEND COSE_INSTALL_TARGETS cose_crypto_openssl)
endif()
if(COSE_FFI_FACTORIES_LIB)
    list(APPEND COSE_INSTALL_TARGETS cose_factories)
endif()

install(TARGETS ${COSE_INSTALL_TARGETS}
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
