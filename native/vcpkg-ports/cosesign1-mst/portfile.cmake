set(VCPKG_LIBRARY_LINKAGE static)

set(SOURCE_PATH "${CURRENT_PORT_DIR}/../../shim")

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DBUILD_TESTING=OFF
    -DCOSESIGN1_SHIM_PACKAGE_NAME=cosesign1_mst
    -DCOSESIGN1_SHIM_BUILD_COMMON=OFF
    -DCOSESIGN1_SHIM_BUILD_VALIDATION=OFF
    -DCOSESIGN1_SHIM_BUILD_X509=OFF
    -DCOSESIGN1_SHIM_BUILD_MST=ON
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(
    PACKAGE_NAME cosesign1_mst
    CONFIG_PATH "lib/cmake/cosesign1_mst"
)

file(INSTALL "${CURRENT_PORT_DIR}/usage" DESTINATION "${CURRENT_PACKAGES_DIR}/share/${PORT}")

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

vcpkg_install_copyright(FILE_LIST "${CURRENT_PORT_DIR}/../../../LICENSE")
