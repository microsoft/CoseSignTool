set(VCPKG_LIBRARY_LINKAGE static)

set(_COSE_CARGO_HINTS "")
if(DEFINED ENV{CARGO})
    list(APPEND _COSE_CARGO_HINTS "$ENV{CARGO}")
endif()
if(DEFINED ENV{CARGO_HOME})
    list(APPEND _COSE_CARGO_HINTS "$ENV{CARGO_HOME}/bin")
endif()
if(DEFINED ENV{USERPROFILE})
    list(APPEND _COSE_CARGO_HINTS "$ENV{USERPROFILE}/.cargo/bin")
endif()

find_program(COSESIGN1_CARGO NAMES cargo cargo.exe HINTS ${_COSE_CARGO_HINTS})
if(NOT COSESIGN1_CARGO)
    message(FATAL_ERROR "The cosesign1-* ports require Rust (cargo). Install Rust (https://rustup.rs) and ensure 'cargo' is on PATH.")
endif()

set(SOURCE_PATH "${CURRENT_PORT_DIR}/../../cosesign1")

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
    -DCOSESIGN1_NATIVE_PACKAGE_NAME=cosesign1_abstractions_ffi
    -DCOSESIGN1_CARGO=${COSESIGN1_CARGO}
    -DCOSESIGN1_NATIVE_BUILD_ABSTRACTIONS=ON
    -DCOSESIGN1_NATIVE_BUILD_VALIDATION=OFF
    -DCOSESIGN1_NATIVE_BUILD_X509=OFF
    -DCOSESIGN1_NATIVE_BUILD_MST=OFF
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(
    PACKAGE_NAME cosesign1_abstractions_ffi
    CONFIG_PATH "lib/cmake/cosesign1_abstractions_ffi"
)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

vcpkg_install_copyright(FILE_LIST "${CURRENT_PORT_DIR}/../../../LICENSE")
