cmake_minimum_required(VERSION 3.23)

project(cosesign1_mst VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)
# tinycbor integration
# - Some environments provide a CMake package (often named "unofficial-tinycbor").
# - vcpkg's tinycbor port provides headers/libs but no tinycborConfig.cmake.
find_package(unofficial-tinycbor CONFIG QUIET)
find_package(tinycbor CONFIG QUIET)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(CURL CONFIG REQUIRED)

# cosesign1_signature is provided by the sibling port.
find_package(cosesign1_signature CONFIG REQUIRED)

set(_cbor_target "")
if(TARGET tinycbor::tinycbor)
  set(_cbor_target tinycbor::tinycbor)
elseif(TARGET unofficial::tinycbor::tinycbor)
  set(_cbor_target unofficial::tinycbor::tinycbor)
elseif(TARGET tinycbor)
  set(_cbor_target tinycbor)
else()
  find_path(TINYCBOR_INCLUDE_DIR NAMES tinycbor/cbor.h)
  find_library(TINYCBOR_LIBRARY_RELEASE NAMES tinycbor PATH_SUFFIXES lib)
  find_library(TINYCBOR_LIBRARY_DEBUG NAMES tinycbor PATH_SUFFIXES debug/lib)
  if (NOT TINYCBOR_INCLUDE_DIR OR (NOT TINYCBOR_LIBRARY_RELEASE AND NOT TINYCBOR_LIBRARY_DEBUG))
    message(FATAL_ERROR "tinycbor not found (no CMake package and could not locate tinycbor/cbor.h + library)")
  endif()

  add_library(tinycbor::tinycbor UNKNOWN IMPORTED)
  set_target_properties(tinycbor::tinycbor PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES "${TINYCBOR_INCLUDE_DIR}"
  )

  if (TINYCBOR_LIBRARY_RELEASE)
    set_target_properties(tinycbor::tinycbor PROPERTIES IMPORTED_LOCATION_RELEASE "${TINYCBOR_LIBRARY_RELEASE}")
    set_property(TARGET tinycbor::tinycbor PROPERTY MAP_IMPORTED_CONFIG_RELWITHDEBINFO Release)
    set_property(TARGET tinycbor::tinycbor PROPERTY MAP_IMPORTED_CONFIG_MINSIZEREL Release)
  endif()

  if (TINYCBOR_LIBRARY_DEBUG)
    set_target_properties(tinycbor::tinycbor PROPERTIES IMPORTED_LOCATION_DEBUG "${TINYCBOR_LIBRARY_DEBUG}")
  endif()

  # If only one of the configs exists, fall back to it for the other.
  if (NOT TINYCBOR_LIBRARY_DEBUG AND TINYCBOR_LIBRARY_RELEASE)
    set_target_properties(tinycbor::tinycbor PROPERTIES IMPORTED_LOCATION_DEBUG "${TINYCBOR_LIBRARY_RELEASE}")
  elseif (NOT TINYCBOR_LIBRARY_RELEASE AND TINYCBOR_LIBRARY_DEBUG)
    set_target_properties(tinycbor::tinycbor PROPERTIES IMPORTED_LOCATION_RELEASE "${TINYCBOR_LIBRARY_DEBUG}")
  endif()

  set(_cbor_target tinycbor::tinycbor)
endif()

add_library(cosesign1_mst
  src/mst_verifier.cpp
  src/jwk_ec_key.cpp
  src/online_key_resolver.cpp
  src/jwks_fetcher_curl.cpp
)

target_include_directories(cosesign1_mst
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(cosesign1_mst
  PUBLIC
    cosesign1::cosesign1_signature
    OpenSSL::Crypto
    ${_cbor_target}
    nlohmann_json::nlohmann_json
    CURL::libcurl
)

target_compile_features(cosesign1_mst PUBLIC cxx_std_20)

if (MSVC)
  target_compile_options(cosesign1_mst PRIVATE /W4 /permissive-)
else()
  target_compile_options(cosesign1_mst PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(TARGETS cosesign1_mst
  EXPORT cosesign1_mstTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/cosesign1_mstConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cosesign1_mstConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/cosesign1_mstConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cosesign1_mst
)

install(EXPORT cosesign1_mstTargets
  FILE cosesign1_mstTargets.cmake
  NAMESPACE cosesign1::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cosesign1_mst
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/cosesign1_mstConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/cosesign1_mstConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cosesign1_mst
)

if (BUILD_TESTING)
  find_package(Catch2 3 CONFIG REQUIRED)

  add_executable(cosesign1_mst_tests
    tests/test_mst_receipt_validation.cpp
  )

  target_link_libraries(cosesign1_mst_tests PRIVATE cosesign1_mst Catch2::Catch2WithMain)

  if (MSVC)
    target_compile_options(cosesign1_mst_tests PRIVATE /W4 /permissive-)
  else()
    target_compile_options(cosesign1_mst_tests PRIVATE -Wall -Wextra -Wpedantic)
  endif()

  include(Catch)
  catch_discover_tests(cosesign1_mst_tests)
endif()
