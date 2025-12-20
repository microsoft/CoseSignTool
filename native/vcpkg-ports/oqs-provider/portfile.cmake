set(VCPKG_LIBRARY_LINKAGE dynamic)

vcpkg_from_github(
    OUT_SOURCE_PATH SOURCE_PATH
    REPO open-quantum-safe/oqs-provider
    REF 0.10.0
    SHA512 42ddc274c7a0291164470edaf21bea810cca0f61a25c73481f4b5d8aab353a6c2dd3a0881f079ddb5cd03424c7541fa9fbca6dbc94339ff13337255b5ee4985c
    HEAD_REF main
    PATCHES
        "${CURRENT_PORT_DIR}/fix-win-openssl-modules-path.patch"
)

vcpkg_cmake_configure(
    SOURCE_PATH "${SOURCE_PATH}"
    OPTIONS
        -DBUILD_TESTING=OFF
        -DOQS_PROVIDER_BUILD_STATIC=OFF
        -DBUILD_SHARED_LIBS=ON
        -DOPENSSL_MODULES_PATH=bin
)

vcpkg_cmake_install()

vcpkg_copy_pdbs()

vcpkg_install_copyright(FILE_LIST "${SOURCE_PATH}/LICENSE.txt")
