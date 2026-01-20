// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cose/cose_sign1.h>
#include <cose/cose_certificates.h>
#include <stdio.h>
#include <stdlib.h>

int main(void) {
    printf("COSE C API Smoke Test\n");
    printf("ABI Version: %u\n", cose_ffi_abi_version());
    
    // Create builder
    cose_validator_builder_t* builder = NULL;
    cose_status_t status = cose_validator_builder_new(&builder);
    if (status != COSE_OK) {
        fprintf(stderr, "Failed to create builder: %d\n", status);
        char* err = cose_last_error_message_utf8();
        if (err) {
            fprintf(stderr, "Error: %s\n", err);
            cose_string_free(err);
        }
        return 1;
    }
    printf("✓ Builder created\n");
    
#ifdef COSE_HAS_CERTIFICATES_PACK
    // Add certificates pack
    status = cose_validator_builder_with_certificates_pack(builder);
    if (status != COSE_OK) {
        fprintf(stderr, "Failed to add certificates pack: %d\n", status);
        char* err = cose_last_error_message_utf8();
        if (err) {
            fprintf(stderr, "Error: %s\n", err);
            cose_string_free(err);
        }
        cose_validator_builder_free(builder);
        return 1;
    }
    printf("✓ Certificates pack added\n");
#endif
    
    // Build validator
    cose_validator_t* validator = NULL;
    status = cose_validator_builder_build(builder, &validator);
    if (status != COSE_OK) {
        fprintf(stderr, "Failed to build validator: %d\n", status);
        char* err = cose_last_error_message_utf8();
        if (err) {
            fprintf(stderr, "Error: %s\n", err);
            cose_string_free(err);
        }
        cose_validator_builder_free(builder);
        return 1;
    }
    printf("✓ Validator built\n");
    
    // Cleanup
    cose_validator_free(validator);
    cose_validator_builder_free(builder);
    
    printf("\n✅ All smoke tests passed\n");
    return 0;
}
