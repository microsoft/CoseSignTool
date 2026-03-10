# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.

# Examples are optional and primarily for developer guidance.
option(COSE_BUILD_EXAMPLES "Build C projection examples" ON)

if(NOT COSE_BUILD_EXAMPLES)
    return()
endif()

if(NOT COSE_FFI_TRUST_LIB)
    message(STATUS "Skipping C examples: trust pack not found (cose_sign1_validation_primitives_ffi)")
    return()
endif()

add_executable(cose_trust_policy_example
    trust_policy_example.c
)

target_link_libraries(cose_trust_policy_example PRIVATE
    cose_sign1
)

add_executable(cose_full_example
    full_example.c
)

# Link multiple libraries for full functionality
target_link_libraries(cose_full_example PRIVATE
    cose_sign1
)

# Full example requires signing, primitives, headers, and DID libraries
if(TARGET cose_signing)
    target_link_libraries(cose_full_example PRIVATE cose_signing)
endif()

if(TARGET cose_primitives)
    target_link_libraries(cose_full_example PRIVATE cose_primitives)
endif()

if(TARGET cose_cwt_headers)
    target_link_libraries(cose_full_example PRIVATE cose_cwt_headers)
endif()

if(TARGET cose_did_x509)
    target_link_libraries(cose_full_example PRIVATE cose_did_x509)
endif()
