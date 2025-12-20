cmake_minimum_required(VERSION 3.23)

project(cosesign1_x509 VERSION 0.1.0 LANGUAGES CXX)

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

add_library(cosesign1_x509
  src/x5c_verifier.cpp
)

target_include_directories(cosesign1_x509
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_link_libraries(cosesign1_x509
  PUBLIC
    cosesign1::cosesign1_signature
    OpenSSL::Crypto
    ${_cbor_target}
)

target_compile_features(cosesign1_x509 PUBLIC cxx_std_20)

if (MSVC)
  target_compile_options(cosesign1_x509 PRIVATE /W4 /permissive-)
else()
  target_compile_options(cosesign1_x509 PRIVATE -Wall -Wextra -Wpedantic)
endif()

install(TARGETS cosesign1_x509
  EXPORT cosesign1_x509Targets
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/cosesign1_x509ConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cosesign1_x509Config.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/cosesign1_x509Config.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cosesign1_x509
)

install(EXPORT cosesign1_x509Targets
  FILE cosesign1_x509Targets.cmake
  NAMESPACE cosesign1::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cosesign1_x509
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/cosesign1_x509Config.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/cosesign1_x509ConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cosesign1_x509
)

if (BUILD_TESTING)
  find_package(Catch2 3 CONFIG REQUIRED)

  add_executable(cosesign1_x509_tests
    tests/test_x5c_verify_es256.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../cosesign1-validation/tests/test_utils.cpp
  )

  target_link_libraries(cosesign1_x509_tests PRIVATE cosesign1_x509 Catch2::Catch2WithMain)

  if (MSVC)
    target_compile_options(cosesign1_x509_tests PRIVATE /W4 /permissive-)
  else()
    target_compile_options(cosesign1_x509_tests PRIVATE -Wall -Wextra -Wpedantic)
  endif()

  include(Catch)
  catch_discover_tests(cosesign1_x509_tests)
endif()
