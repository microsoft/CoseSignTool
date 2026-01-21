# CMake package config for cosesign1-validation-native (vcpkg)
# Provides:
#   - cosesign1_validation_native::cose_sign1
#   - cosesign1_validation_native::cose_sign1_cpp (when built/installed with feature "cpp")

cmake_minimum_required(VERSION 3.20)

get_filename_component(_COSE_IMPORT_PREFIX "${CMAKE_CURRENT_LIST_DIR}/../.." ABSOLUTE)

set(_COSE_INCLUDE_DIR "${_COSE_IMPORT_PREFIX}/include")

function(_cose_add_imported_static name libbase)
    if(TARGET ${name})
        return()
    endif()

    add_library(${name} STATIC IMPORTED GLOBAL)

    if(WIN32)
        set(_rel "${_COSE_IMPORT_PREFIX}/lib/${libbase}.lib")
        set(_dbg "${_COSE_IMPORT_PREFIX}/debug/lib/${libbase}.lib")
    else()
        set(_rel "${_COSE_IMPORT_PREFIX}/lib/lib${libbase}.a")
        set(_dbg "${_COSE_IMPORT_PREFIX}/debug/lib/lib${libbase}.a")
    endif()

    set_target_properties(${name} PROPERTIES
        IMPORTED_LOCATION_RELEASE "${_rel}"
        IMPORTED_LOCATION_DEBUG "${_dbg}"
    )
endfunction()

_cose_add_imported_static(cosesign1_validation_native::ffi_base cose_sign1_validation_ffi)

function(_cose_try_add_pack pack_target libbase)
    if(WIN32)
        set(_probe_rel "${_COSE_IMPORT_PREFIX}/lib/${libbase}.lib")
    else()
        set(_probe_rel "${_COSE_IMPORT_PREFIX}/lib/lib${libbase}.a")
    endif()

    if(EXISTS "${_probe_rel}")
        _cose_add_imported_static(${pack_target} ${libbase})
        set(${pack_target}_ENABLED TRUE PARENT_SCOPE)
    else()
        set(${pack_target}_ENABLED FALSE PARENT_SCOPE)
    endif()
endfunction()

_cose_try_add_pack(cosesign1_validation_native::ffi_certificates cose_sign1_validation_ffi_certificates)
_cose_try_add_pack(cosesign1_validation_native::ffi_mst cose_sign1_validation_ffi_mst)
_cose_try_add_pack(cosesign1_validation_native::ffi_akv cose_sign1_validation_ffi_akv)
_cose_try_add_pack(cosesign1_validation_native::ffi_trust cose_sign1_validation_ffi_trust)

if(NOT TARGET cosesign1_validation_native::cose_sign1)
    add_library(cosesign1_validation_native::cose_sign1 INTERFACE IMPORTED GLOBAL)
    set_target_properties(cosesign1_validation_native::cose_sign1 PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES "${_COSE_INCLUDE_DIR}"
    )

    target_link_libraries(cosesign1_validation_native::cose_sign1 INTERFACE
        cosesign1_validation_native::ffi_base
    )

    if(cosesign1_validation_native::ffi_certificates_ENABLED)
        target_link_libraries(cosesign1_validation_native::cose_sign1 INTERFACE cosesign1_validation_native::ffi_certificates)
        target_compile_definitions(cosesign1_validation_native::cose_sign1 INTERFACE COSE_HAS_CERTIFICATES_PACK)
    endif()
    if(cosesign1_validation_native::ffi_mst_ENABLED)
        target_link_libraries(cosesign1_validation_native::cose_sign1 INTERFACE cosesign1_validation_native::ffi_mst)
        target_compile_definitions(cosesign1_validation_native::cose_sign1 INTERFACE COSE_HAS_MST_PACK)
    endif()
    if(cosesign1_validation_native::ffi_akv_ENABLED)
        target_link_libraries(cosesign1_validation_native::cose_sign1 INTERFACE cosesign1_validation_native::ffi_akv)
        target_compile_definitions(cosesign1_validation_native::cose_sign1 INTERFACE COSE_HAS_AKV_PACK)
    endif()
    if(cosesign1_validation_native::ffi_trust_ENABLED)
        target_link_libraries(cosesign1_validation_native::cose_sign1 INTERFACE cosesign1_validation_native::ffi_trust)
        target_compile_definitions(cosesign1_validation_native::cose_sign1 INTERFACE COSE_HAS_TRUST_PACK)
    endif()

    if(WIN32)
        target_link_libraries(cosesign1_validation_native::cose_sign1 INTERFACE
            ws2_32 advapi32 userenv bcrypt ntdll
        )
    elseif(UNIX)
        target_link_libraries(cosesign1_validation_native::cose_sign1 INTERFACE
            pthread dl m
        )
    endif()
endif()

if(EXISTS "${_COSE_INCLUDE_DIR}/cose/cose.hpp")
    if(NOT TARGET cosesign1_validation_native::cose_sign1_cpp)
        add_library(cosesign1_validation_native::cose_sign1_cpp INTERFACE IMPORTED GLOBAL)
        set_target_properties(cosesign1_validation_native::cose_sign1_cpp PROPERTIES
            INTERFACE_INCLUDE_DIRECTORIES "${_COSE_INCLUDE_DIR}"
        )
        target_link_libraries(cosesign1_validation_native::cose_sign1_cpp INTERFACE cosesign1_validation_native::cose_sign1)
    endif()
endif()
