# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Basic smoke test for C API
add_executable(smoke_test smoke_test.c)
target_link_libraries(smoke_test PRIVATE cose_sign1)

add_test(NAME smoke_test COMMAND smoke_test)
