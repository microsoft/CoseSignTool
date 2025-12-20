set(VCPKG_LIBRARY_LINKAGE static)

set(SOURCE_PATH "${CURRENT_PORT_DIR}/../../cosesign1-validation")

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DBUILD_TESTING=OFF
)

vcpkg_cmake_install()

vcpkg_cmake_config_fixup(
    PACKAGE_NAME cosesign1_validation
    CONFIG_PATH "lib/cmake/cosesign1_validation"
)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

vcpkg_install_copyright(FILE_LIST "${CURRENT_PORT_DIR}/../../../LICENSE")
