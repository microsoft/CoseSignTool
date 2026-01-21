# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# This is an overlay port intended for development/publishing from this repo.
# It builds the Rust FFI staticlibs via cargo and installs the C/C++ projection headers.

vcpkg_check_linkage(ONLY_STATIC_LIBRARY)

# As an overlay port in this repo, point directly at the repo root.
set(_COSE_REPO_ROOT "${CMAKE_CURRENT_LIST_DIR}/../../..")

if(NOT EXISTS "${_COSE_REPO_ROOT}/native/rust/Cargo.toml")
    message(FATAL_ERROR "Expected repo root at ${_COSE_REPO_ROOT} (native/rust/Cargo.toml not found)")
endif()

set(_RUST_WORKSPACE_DIR "${_COSE_REPO_ROOT}/native/rust")

# Locate cargo (vcpkg's build environment may not have rustup on PATH).
set(_COSE_CARGO "")
if(DEFINED ENV{CARGO} AND NOT "$ENV{CARGO}" STREQUAL "")
    set(_COSE_CARGO "$ENV{CARGO}")
elseif(VCPKG_TARGET_IS_WINDOWS AND DEFINED ENV{USERPROFILE} AND EXISTS "$ENV{USERPROFILE}/.cargo/bin/cargo.exe")
    set(_COSE_CARGO "$ENV{USERPROFILE}/.cargo/bin/cargo.exe")
elseif(DEFINED ENV{HOME} AND EXISTS "$ENV{HOME}/.cargo/bin/cargo")
    set(_COSE_CARGO "$ENV{HOME}/.cargo/bin/cargo")
else()
    find_program(_COSE_CARGO cargo)
endif()

if(_COSE_CARGO STREQUAL "")
    message(FATAL_ERROR "cargo not found. Install Rust (rustup) and ensure cargo is on PATH, or set the CARGO environment variable.")
endif()

# Map vcpkg architecture to a Rust target triple where possible.
set(_RUST_TARGET "")
if(VCPKG_CMAKE_SYSTEM_NAME STREQUAL "WindowsStore")
    message(FATAL_ERROR "UWP not supported by this port")
endif()

if(VCPKG_TARGET_IS_WINDOWS)
    if(VCPKG_TARGET_ARCHITECTURE STREQUAL "x64")
        set(_RUST_TARGET "x86_64-pc-windows-msvc")
    elseif(VCPKG_TARGET_ARCHITECTURE STREQUAL "x86")
        set(_RUST_TARGET "i686-pc-windows-msvc")
    elseif(VCPKG_TARGET_ARCHITECTURE STREQUAL "arm64")
        set(_RUST_TARGET "aarch64-pc-windows-msvc")
    endif()
endif()

# Build list based on requested features.
set(_PACKAGES_TO_BUILD
    cose_sign1_validation_ffi
)

if("certificates" IN_LIST FEATURES)
    list(APPEND _PACKAGES_TO_BUILD cose_sign1_validation_ffi_certificates)
endif()
if("mst" IN_LIST FEATURES)
    list(APPEND _PACKAGES_TO_BUILD cose_sign1_validation_ffi_mst)
endif()
if("akv" IN_LIST FEATURES)
    list(APPEND _PACKAGES_TO_BUILD cose_sign1_validation_ffi_akv)
endif()
if("trust" IN_LIST FEATURES)
    list(APPEND _PACKAGES_TO_BUILD cose_sign1_validation_ffi_trust)
endif()

function(_cose_cargo_build config)
    if(config STREQUAL "debug")
        set(_CARGO_PROFILE "")
        set(_TARGET_SUBDIR "debug")
    else()
        set(_CARGO_PROFILE "--release")
        set(_TARGET_SUBDIR "release")
    endif()

    set(_CARGO_TARGET_ARGS "")
    if(NOT _RUST_TARGET STREQUAL "")
        set(_CARGO_TARGET_ARGS "--target" "${_RUST_TARGET}")
        set(_TARGET_SUBDIR "${_RUST_TARGET}/${_TARGET_SUBDIR}")
    endif()

    foreach(_pkg IN LISTS _PACKAGES_TO_BUILD)
        vcpkg_execute_required_process(
            COMMAND "${_COSE_CARGO}" build ${_CARGO_PROFILE} --package ${_pkg} --locked ${_CARGO_TARGET_ARGS}
            WORKING_DIRECTORY "${_RUST_WORKSPACE_DIR}"
            LOGNAME "cargo-build-${_pkg}-${config}"
        )
    endforeach()

    set(_RUST_OUT_DIR "${_RUST_WORKSPACE_DIR}/target/${_TARGET_SUBDIR}")
    if(NOT EXISTS "${_RUST_OUT_DIR}")
        message(FATAL_ERROR "Rust output dir not found: ${_RUST_OUT_DIR}")
    endif()

    # Install staticlibs produced by the FFI crates.
    foreach(_pkg IN LISTS _PACKAGES_TO_BUILD)
        set(_libname "${_pkg}")

        if(VCPKG_TARGET_IS_WINDOWS)
            set(_ext ".lib")
        else()
            set(_ext ".a")
            set(_libname "lib${_libname}")
        endif()

        set(_src "${_RUST_OUT_DIR}/${_libname}${_ext}")
        if(NOT EXISTS "${_src}")
            message(FATAL_ERROR "Expected Rust static library not found: ${_src}")
        endif()

        if(config STREQUAL "debug")
            file(INSTALL "${_src}" DESTINATION "${CURRENT_PACKAGES_DIR}/debug/lib")
        else()
            file(INSTALL "${_src}" DESTINATION "${CURRENT_PACKAGES_DIR}/lib")
        endif()
    endforeach()
endfunction()

_cose_cargo_build(debug)
_cose_cargo_build(release)

# Install headers.
file(INSTALL "${_COSE_REPO_ROOT}/native/c/include/" DESTINATION "${CURRENT_PACKAGES_DIR}/include")
if("cpp" IN_LIST FEATURES)
    file(INSTALL "${_COSE_REPO_ROOT}/native/c_pp/include/" DESTINATION "${CURRENT_PACKAGES_DIR}/include")
endif()

# CMake config + usage docs
file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/cose_sign1_validationConfig.cmake" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}")
file(INSTALL "${CMAKE_CURRENT_LIST_DIR}/usage" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}")

# Native developer docs
file(INSTALL "${_COSE_REPO_ROOT}/native/ARCHITECTURE.md" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}/docs/native")
file(INSTALL DIRECTORY "${_COSE_REPO_ROOT}/native/docs/" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}/docs/native/docs" FILES_MATCHING PATTERN "*.md")
file(INSTALL DIRECTORY "${_COSE_REPO_ROOT}/native/c/docs/" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}/docs/native/c/docs" FILES_MATCHING PATTERN "*.md")
file(INSTALL DIRECTORY "${_COSE_REPO_ROOT}/native/c_pp/docs/" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}/docs/native/c_pp/docs" FILES_MATCHING PATTERN "*.md")

# License
file(INSTALL "${_COSE_REPO_ROOT}/LICENSE" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}" RENAME copyright)
