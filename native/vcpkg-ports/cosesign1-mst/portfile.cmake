set(VCPKG_LIBRARY_LINKAGE static)
set(VCPKG_POLICY_EMPTY_INCLUDE_FOLDER enabled)

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
    -DCOSESIGN1_NATIVE_PACKAGE_NAME=cosesign1_mst
    -DCOSESIGN1_CARGO=${COSESIGN1_CARGO}
    -DCOSESIGN1_NATIVE_BUILD_ABSTRACTIONS=OFF
    -DCOSESIGN1_NATIVE_BUILD_VALIDATION=OFF
    -DCOSESIGN1_NATIVE_BUILD_X509=OFF
    -DCOSESIGN1_NATIVE_BUILD_MST=ON
)

vcpkg_cmake_install()

# Headers are shared and owned by the `cosesign1-abstractions` port.
file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/include")

vcpkg_cmake_config_fixup(
    PACKAGE_NAME cosesign1_mst
    CONFIG_PATH "lib/cmake/cosesign1_mst"
)

file(INSTALL "${CURRENT_PORT_DIR}/usage" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}")

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

vcpkg_install_copyright(FILE_LIST "${CURRENT_PORT_DIR}/../../../LICENSE")
