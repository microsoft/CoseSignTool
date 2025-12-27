cmake_minimum_required(VERSION 3.21)

project(cosesign1_native_tests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(CTest)
enable_testing()

find_package(Catch2 3 CONFIG REQUIRED)
find_package(cosesign1_abstractions_ffi CONFIG REQUIRED)
find_package(cosesign1_validation CONFIG REQUIRED)
find_package(cosesign1_mst CONFIG REQUIRED)
find_package(cosesign1_x509 CONFIG REQUIRED)

add_executable(cosesign1_native_tests
    test_cosesign1_hpp.cpp
)

target_link_libraries(cosesign1_native_tests PRIVATE
    Catch2::Catch2WithMain
    cosesign1::abstractions
    cosesign1::validation
    cosesign1::mst
    cosesign1::x509
)

add_test(NAME cosesign1_native_tests COMMAND cosesign1_native_tests)
