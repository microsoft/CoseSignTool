cmake_minimum_required(VERSION 3.23)

project(cosesign1_hello_world LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_package(cosesign1_common CONFIG REQUIRED)
find_package(cosesign1_validation CONFIG REQUIRED)
find_package(cosesign1_x509 CONFIG REQUIRED)
find_package(cosesign1_mst CONFIG REQUIRED)

add_executable(cosesign1_hello_world
  main.cpp
)

target_link_libraries(cosesign1_hello_world PRIVATE
  cosesign1::cosesign1_common
  cosesign1::cosesign1_validation
  cosesign1::cosesign1_x509
  cosesign1::cosesign1_mst
)

if (MSVC)
  target_compile_options(cosesign1_hello_world PRIVATE /W4 /permissive-)
else()
  target_compile_options(cosesign1_hello_world PRIVATE -Wall -Wextra -Wpedantic)
endif()
