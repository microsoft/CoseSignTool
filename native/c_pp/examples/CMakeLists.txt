# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Examples are optional and primarily for developer guidance.
option(COSE_CPP_BUILD_EXAMPLES "Build C++ projection examples" ON)

if(NOT COSE_CPP_BUILD_EXAMPLES)
    return()
endif()

if(NOT COSE_FFI_TRUST_LIB)
    message(STATUS "Skipping C++ examples: trust pack not found (cose_sign1_validation_ffi_trust)")
    return()
endif()

add_executable(cose_trust_policy_example_cpp
    trust_policy_example.cpp
)

target_link_libraries(cose_trust_policy_example_cpp PRIVATE
    cose_sign1_cpp
)
