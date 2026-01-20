# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Basic smoke test for C++ API
add_executable(smoke_test_cpp smoke_test.cpp)
target_link_libraries(smoke_test_cpp PRIVATE cose_sign1_cpp)

add_test(NAME smoke_test_cpp COMMAND smoke_test_cpp)
