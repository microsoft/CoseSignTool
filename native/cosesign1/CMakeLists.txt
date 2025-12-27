cmake_minimum_required(VERSION 3.21)

project(cosesign1_native LANGUAGES C)

include(GNUInstallDirs)

# vcpkg build environments on Windows don't always preserve PATH in a way that
# makes `cargo` discoverable from custom commands. Resolve it once up-front and
# use the absolute path.
set(COSESIGN1_CARGO "" CACHE FILEPATH "Path to cargo executable")
if(NOT COSESIGN1_CARGO)
  find_program(COSESIGN1_CARGO NAMES cargo cargo.exe)
endif()
if(NOT COSESIGN1_CARGO AND WIN32)
  set(_COSE_CARGO_DEFAULT "$ENV{USERPROFILE}/.cargo/bin/cargo.exe")
  if(EXISTS "${_COSE_CARGO_DEFAULT}")
    set(COSESIGN1_CARGO "${_COSE_CARGO_DEFAULT}")
  endif()
endif()
if(NOT COSESIGN1_CARGO)
  message(FATAL_ERROR "Rust toolchain not found: 'cargo' is required. Install Rust (https://rustup.rs) or set -DCOSESIGN1_CARGO=<path-to-cargo>.")
endif()

option(COSESIGN1_NATIVE_BUILD_ABSTRACTIONS "Build cosesign1_abstractions_ffi" OFF)
option(COSESIGN1_NATIVE_BUILD_VALIDATION "Build cosesign1_validation" OFF)
option(COSESIGN1_NATIVE_BUILD_X509 "Build cosesign1_x509" OFF)
option(COSESIGN1_NATIVE_BUILD_MST "Build cosesign1_mst" OFF)

set(COSESIGN1_NATIVE_PACKAGE_NAME "cosesign1_abstractions_ffi" CACHE STRING "vcpkg/cmake package name")

# Resolve build profile for cargo.
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
  set(_COSE_RUST_PROFILE "debug")
  set(_COSE_CARGO_FLAGS "")
else()
  set(_COSE_RUST_PROFILE "release")
  set(_COSE_CARGO_FLAGS "--release")
endif()

set(_COSE_RUST_WORKSPACE "${CMAKE_CURRENT_LIST_DIR}/../../rust")
set(_COSE_RUST_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/rust-target")

if(WIN32)
  set(_COSE_LIB_PREFIX "")
  set(_COSE_LIB_SUFFIX ".lib")
else()
  set(_COSE_LIB_PREFIX "lib")
  set(_COSE_LIB_SUFFIX ".a")
endif()

function(cosesign1_add_rust_staticlib crate_name lib_basename)
  set(_out_dir "${CMAKE_CURRENT_BINARY_DIR}/out")
  file(MAKE_DIRECTORY "${_out_dir}")

  set(_built "${_COSE_RUST_TARGET_DIR}/${_COSE_RUST_PROFILE}/${_COSE_LIB_PREFIX}${lib_basename}${_COSE_LIB_SUFFIX}")
  set(_out_lib "${_out_dir}/${_COSE_LIB_PREFIX}${lib_basename}${_COSE_LIB_SUFFIX}")

  add_custom_command(
    OUTPUT "${_out_lib}"
    COMMAND "${COSESIGN1_CARGO}" build --manifest-path "${_COSE_RUST_WORKSPACE}/Cargo.toml" -p "${crate_name}" ${_COSE_CARGO_FLAGS} --target-dir "${_COSE_RUST_TARGET_DIR}"
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different "${_built}" "${_out_lib}"
    WORKING_DIRECTORY "${_COSE_RUST_WORKSPACE}"
    VERBATIM
  )

  add_custom_target(${lib_basename}_build ALL DEPENDS "${_out_lib}")

  # Install the built static library.
  install(FILES "${_out_lib}" DESTINATION "${CMAKE_INSTALL_LIBDIR}")
endfunction()

function(cosesign1_install_public_headers)
  install(FILES
    "${CMAKE_CURRENT_LIST_DIR}/abstractions/include/abstractions.h"
    "${CMAKE_CURRENT_LIST_DIR}/abstractions/include/abstractions.hpp"
    "${CMAKE_CURRENT_LIST_DIR}/include/cosesign1.h"
    "${CMAKE_CURRENT_LIST_DIR}/include/cosesign1.hpp"
    "${CMAKE_CURRENT_LIST_DIR}/x509/include/x509.h"
    "${CMAKE_CURRENT_LIST_DIR}/x509/include/x509.hpp"
    "${CMAKE_CURRENT_LIST_DIR}/mst/include/mst.h"
    "${CMAKE_CURRENT_LIST_DIR}/mst/include/mst.hpp"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/cosesign1"
  )
endfunction()

set(_enabled_count 0)

if(COSESIGN1_NATIVE_BUILD_ABSTRACTIONS)
  math(EXPR _enabled_count "${_enabled_count}+1")
  cosesign1_add_rust_staticlib("cosesign1-ffi-abstractions" "cosesign1_abstractions_ffi")
endif()

if(COSESIGN1_NATIVE_BUILD_VALIDATION)
  math(EXPR _enabled_count "${_enabled_count}+1")
  cosesign1_add_rust_staticlib("cosesign1-ffi" "cosesign1_validation")
endif()

if(COSESIGN1_NATIVE_BUILD_X509)
  math(EXPR _enabled_count "${_enabled_count}+1")
  cosesign1_add_rust_staticlib("cosesign1-ffi-x509" "cosesign1_x509")
endif()

if(COSESIGN1_NATIVE_BUILD_MST)
  math(EXPR _enabled_count "${_enabled_count}+1")
  cosesign1_add_rust_staticlib("cosesign1-ffi-mst" "cosesign1_mst")
endif()

if(_enabled_count EQUAL 0)
  message(FATAL_ERROR "No COSESIGN1_NATIVE_BUILD_* component enabled")
endif()

cosesign1_install_public_headers()

# Install a minimal config file so vcpkg-cmake-config can fix it up.
set(_COSE_CONFIG_DIR "${CMAKE_INSTALL_LIBDIR}/cmake/${COSESIGN1_NATIVE_PACKAGE_NAME}")
set(_COSE_CONFIG_FILE "${CMAKE_CURRENT_BINARY_DIR}/${COSESIGN1_NATIVE_PACKAGE_NAME}Config.cmake")

configure_file(
  "${CMAKE_CURRENT_LIST_DIR}/cmake/Config.cmake.in"
  "${_COSE_CONFIG_FILE}"
  @ONLY
)

install(FILES "${_COSE_CONFIG_FILE}" DESTINATION "${_COSE_CONFIG_DIR}")
