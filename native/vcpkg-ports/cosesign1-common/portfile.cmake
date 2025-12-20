set(VCPKG_LIBRARY_LINKAGE static)

set(SOURCE_PATH "${CURRENT_PORT_DIR}/../../cosesign1-common")

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DBUILD_TESTING=OFF
)

vcpkg_cmake_install()

# Header-only project: CMake config may only be installed for release.
# vcpkg_cmake_config_fixup expects the config to exist under both lib/ and debug/lib/.
set(_cfg_rel "${CURRENT_PACKAGES_DIR}/lib/cmake/cosesign1_common")
set(_cfg_dbg "${CURRENT_PACKAGES_DIR}/debug/lib/cmake/cosesign1_common")
if(EXISTS "${_cfg_rel}" AND NOT EXISTS "${_cfg_dbg}")
    file(MAKE_DIRECTORY "${CURRENT_PACKAGES_DIR}/debug/lib/cmake")
    file(COPY "${_cfg_rel}" DESTINATION "${CURRENT_PACKAGES_DIR}/debug/lib/cmake")
endif()

vcpkg_cmake_config_fixup(
    PACKAGE_NAME cosesign1_common
    CONFIG_PATH "lib/cmake/cosesign1_common"
)

# Header-only port: remove empty library directories to avoid vcpkg warnings.
file(REMOVE_RECURSE
    "${CURRENT_PACKAGES_DIR}/lib"
    "${CURRENT_PACKAGES_DIR}/debug/lib"
)

file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug/include")

# Avoid leaving an empty debug directory around (vcpkg post-build check).
file(GLOB _cosesign1_common_debug_children "${CURRENT_PACKAGES_DIR}/debug/*")
if (NOT _cosesign1_common_debug_children)
    file(REMOVE_RECURSE "${CURRENT_PACKAGES_DIR}/debug")
endif()

vcpkg_install_copyright(FILE_LIST "${CURRENT_PORT_DIR}/../../../LICENSE")
