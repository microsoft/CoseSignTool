cmake_minimum_required(VERSION 3.21)

project(cosesign1_c_hello_world LANGUAGES C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_executable(cosesign1_c_hello_world main.c)

find_package(cosesign1_abstractions_ffi CONFIG REQUIRED)
find_package(cosesign1_validation CONFIG REQUIRED)
find_package(cosesign1_mst CONFIG REQUIRED)
find_package(cosesign1_x509 CONFIG REQUIRED)

target_link_libraries(cosesign1_c_hello_world PRIVATE
	cosesign1::abstractions
	cosesign1::validation
	cosesign1::mst
	cosesign1::x509
)
