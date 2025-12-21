cmake_minimum_required(VERSION 3.23)

project(cosesign1_common VERSION 0.1.5 LANGUAGES CXX)

include(GNUInstallDirs)
include(CTest)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Header-only helper library.
add_library(cosesign1_common INTERFACE)
add_library(cosesign1::cosesign1_common ALIAS cosesign1_common)

target_include_directories(cosesign1_common
  INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

target_compile_features(cosesign1_common INTERFACE cxx_std_20)

# Consumers need tinycbor headers.
find_package(unofficial-tinycbor CONFIG QUIET)
find_package(tinycbor CONFIG QUIET)

if(TARGET tinycbor::tinycbor)
  target_link_libraries(cosesign1_common INTERFACE tinycbor::tinycbor)
elseif(TARGET unofficial::tinycbor::tinycbor)
  target_link_libraries(cosesign1_common INTERFACE unofficial::tinycbor::tinycbor)
elseif(TARGET tinycbor)
  target_link_libraries(cosesign1_common INTERFACE tinycbor)
else()
  find_path(TINYCBOR_INCLUDE_DIR NAMES tinycbor/cbor.h)
  find_library(TINYCBOR_LIBRARY NAMES tinycbor)
  if (NOT TINYCBOR_INCLUDE_DIR OR NOT TINYCBOR_LIBRARY)
    message(FATAL_ERROR "tinycbor not found (could not locate tinycbor/cbor.h + library)")
  endif()

  add_library(tinycbor::tinycbor UNKNOWN IMPORTED)
  set_target_properties(tinycbor::tinycbor PROPERTIES
    IMPORTED_LOCATION "${TINYCBOR_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${TINYCBOR_INCLUDE_DIR}"
  )
  target_link_libraries(cosesign1_common INTERFACE tinycbor::tinycbor)
endif()

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
  ${CMAKE_CURRENT_BINARY_DIR}/cosesign1_commonConfigVersion.cmake
  VERSION ${PROJECT_VERSION}
  COMPATIBILITY SameMajorVersion
)

configure_package_config_file(
  ${CMAKE_CURRENT_SOURCE_DIR}/cmake/cosesign1_commonConfig.cmake.in
  ${CMAKE_CURRENT_BINARY_DIR}/cosesign1_commonConfig.cmake
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cosesign1_common
)

install(TARGETS cosesign1_common
  EXPORT cosesign1_commonTargets
)

install(EXPORT cosesign1_commonTargets
  FILE cosesign1_commonTargets.cmake
  NAMESPACE cosesign1::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cosesign1_common
)

install(FILES
  ${CMAKE_CURRENT_BINARY_DIR}/cosesign1_commonConfig.cmake
  ${CMAKE_CURRENT_BINARY_DIR}/cosesign1_commonConfigVersion.cmake
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/cosesign1_common
)

if (BUILD_TESTING)
  find_package(Catch2 3 CONFIG REQUIRED)

  add_executable(cosesign1_common_tests
    tests/test_cose_sign1_model.cpp
  )

  target_link_libraries(cosesign1_common_tests
    PRIVATE
      cosesign1_common
      Catch2::Catch2WithMain
  )

  if (MSVC)
    target_compile_options(cosesign1_common_tests PRIVATE /W4 /permissive-)
  else()
    target_compile_options(cosesign1_common_tests PRIVATE -Wall -Wextra -Wpedantic)
  endif()

  include(Catch)
  catch_discover_tests(cosesign1_common_tests)
endif()
