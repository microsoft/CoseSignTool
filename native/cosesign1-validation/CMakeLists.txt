cmake_minimum_required(VERSION 3.23)

project(cosesign1_signature VERSION 0.1.0 LANGUAGES CXX)

include(GNUInstallDirs)
include(CTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

option(COSESIGN1_ENABLE_PQC "Enable PQC signature algorithms via liboqs" ON)
if (COSESIGN1_ENABLE_PQC)
  find_package(liboqs CONFIG REQUIRED)
endif()

# tinycbor integration
# - Some environments provide a CMake package (often named "unofficial-tinycbor").
# - vcpkg's tinycbor port provides headers/libs but no tinycborConfig.cmake.
find_package(unofficial-tinycbor CONFIG QUIET)
find_package(tinycbor CONFIG QUIET)

set(_cbor_target "")
if(TARGET tinycbor::tinycbor)
  set(_cbor_target tinycbor::tinycbor)
elseif(TARGET unofficial::tinycbor::tinycbor)
  set(_cbor_target unofficial::tinycbor::tinycbor)
elseif(TARGET tinycbor)
  set(_cbor_target tinycbor)
else()
  find_path(TINYCBOR_INCLUDE_DIR NAMES tinycbor/cbor.h)
  find_library(TINYCBOR_LIBRARY NAMES tinycbor)
  if (NOT TINYCBOR_INCLUDE_DIR OR NOT TINYCBOR_LIBRARY)
    message(FATAL_ERROR "tinycbor not found (no CMake package and could not locate tinycbor/cbor.h + library)")
  endif()

  add_library(tinycbor::tinycbor UNKNOWN IMPORTED)
  set_target_properties(tinycbor::tinycbor PROPERTIES
    IMPORTED_LOCATION "${TINYCBOR_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${TINYCBOR_INCLUDE_DIR}"
  )
  set(_cbor_target tinycbor::tinycbor)
endif()

add_library(cosesign1_signature
  src/cose_sign1_verifier.cpp
  src/cose_sign1_hash_message_verifier.cpp
  src/internal/openssl_utils.cpp
  src/internal/coverage_anchors.cpp
  src/internal/coverage_hooks.cpp
  src/internal/oqs_utils.cpp
)

target_include_directories(cosesign1_signature
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(cosesign1_signature
  PUBLIC
    OpenSSL::Crypto
    ${_cbor_target}
    $<$<BOOL:${COSESIGN1_ENABLE_PQC}>:OQS::oqs>
)

if (COSESIGN1_ENABLE_PQC)
  target_compile_definitions(cosesign1_signature PUBLIC COSESIGN1_ENABLE_PQC=1)
endif()

target_compile_features(cosesign1_signature PUBLIC cxx_std_20)

# Conservative warnings; keep cross-platform.
if (MSVC)
  target_compile_options(cosesign1_signature PRIVATE /W4 /permissive-)
else()
  target_compile_options(cosesign1_signature PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(TARGETS cosesign1_signature
  EXPORT cosesign1_signatureTargets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/cosesign1_signatureConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cosesign1_signatureConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/cosesign1_signatureConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cosesign1_signature
)

install(EXPORT cosesign1_signatureTargets
  FILE cosesign1_signatureTargets.cmake
  NAMESPACE cosesign1::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cosesign1_signature
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/cosesign1_signatureConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/cosesign1_signatureConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cosesign1_signature
)

if (BUILD_TESTING)
  find_package(Catch2 3 CONFIG REQUIRED)

  add_executable(cosesign1_signature_tests
    tests/test_validation_result.cpp
    tests/test_cose_sign1_validation_builder.cpp
    tests/test_verify_es256.cpp
    tests/test_verify_detached_payload.cpp
    tests/test_verify_bad_signature.cpp
    tests/test_verify_ps256.cpp
    tests/test_verify_mldsa.cpp
    tests/test_verify_more_cases.cpp
    tests/test_cose_sign1_hash_message_verifier.cpp
    tests/test_coverage_misc.cpp
    tests/test_openssl_utils.cpp
    tests/test_utils.cpp
  )

  target_link_libraries(cosesign1_signature_tests PRIVATE cosesign1_signature Catch2::Catch2WithMain)

  if (MSVC)
    target_compile_options(cosesign1_signature_tests PRIVATE /W4 /permissive-)
  else()
    target_compile_options(cosesign1_signature_tests PRIVATE -Wall -Wextra -Wpedantic)
  endif()

  include(Catch)
  catch_discover_tests(cosesign1_signature_tests)
endif()
