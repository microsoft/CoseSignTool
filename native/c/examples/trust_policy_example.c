// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cose/cose_sign1.h>
#include <cose/cose_trust.h>

#ifdef COSE_HAS_CERTIFICATES_PACK
#include <cose/cose_certificates.h>
#endif

#ifdef COSE_HAS_MST_PACK
#include <cose/cose_mst.h>
#endif

#ifdef COSE_HAS_AKV_PACK
#include <cose/cose_azure_key_vault.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void print_last_error_and_free(void) {
    char* err = cose_last_error_message_utf8();
    fprintf(stderr, "%s\n", err ? err : "(no error message)");
    if (err) cose_string_free(err);
}

static bool read_file_bytes(const char* path, uint8_t** out_bytes, size_t* out_len) {
    *out_bytes = NULL;
    *out_len = 0;

    FILE* f = NULL;
#if defined(_MSC_VER)
    if (fopen_s(&f, path, "rb") != 0) {
        return false;
    }
#else
    f = fopen(path, "rb");
    if (!f) {
        return false;
    }
#endif

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return false;
    }

    long size = ftell(f);
    if (size < 0) {
        fclose(f);
        return false;
    }

    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return false;
    }

    uint8_t* buf = (uint8_t*)malloc((size_t)size);
    if (!buf) {
        fclose(f);
        return false;
    }

    size_t read = fread(buf, 1, (size_t)size, f);
    fclose(f);

    if (read != (size_t)size) {
        free(buf);
        return false;
    }

    *out_bytes = buf;
    *out_len = (size_t)size;
    return true;
}

#define COSE_CHECK(call) \
    do { \
        cose_status_t _st = (call); \
        if (_st != COSE_OK) { \
            fprintf(stderr, "FAILED: %s\n", #call); \
            print_last_error_and_free(); \
            goto cleanup; \
        } \
    } while (0)

static void usage(const char* argv0) {
    fprintf(stderr,
            "Usage:\n"
            "  %s <cose_sign1.cose> [detached_payload.bin]\n\n"
            "Notes:\n"
            "- This example builds a custom trust policy, compiles it to a bundled plan, and attaches it\n"
            "  to the validator builder before validating the message.\n",
            argv0);
}

int main(int argc, char** argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    const char* cose_path = argv[1];
    const char* payload_path = (argc >= 3) ? argv[2] : NULL;

    uint8_t* cose_bytes = NULL;
    size_t cose_len = 0;

    uint8_t* payload_bytes = NULL;
    size_t payload_len = 0;

    cose_validator_builder_t* builder = NULL;
    cose_trust_policy_builder_t* policy = NULL;
    cose_compiled_trust_plan_t* plan = NULL;
    cose_validator_t* validator = NULL;
    cose_validation_result_t* result = NULL;

    if (!read_file_bytes(cose_path, &cose_bytes, &cose_len)) {
        fprintf(stderr, "Failed to read COSE file: %s\n", cose_path);
        return 2;
    }

    if (payload_path) {
        if (!read_file_bytes(payload_path, &payload_bytes, &payload_len)) {
            fprintf(stderr, "Failed to read detached payload file: %s\n", payload_path);
            free(cose_bytes);
            return 2;
        }
    }

    // 1) Builder + packs
    COSE_CHECK(cose_validator_builder_new(&builder));

#ifdef COSE_HAS_CERTIFICATES_PACK
    COSE_CHECK(cose_validator_builder_with_certificates_pack(builder));
#endif
#ifdef COSE_HAS_MST_PACK
    COSE_CHECK(cose_validator_builder_with_mst_pack(builder));
#endif
#ifdef COSE_HAS_AKV_PACK
    COSE_CHECK(cose_validator_builder_with_akv_pack(builder));
#endif

    // 2) Custom trust policy bound to builder's packs
    COSE_CHECK(cose_trust_policy_builder_new_from_validator_builder(builder, &policy));

    // Message-scope requirements (safe to rely on trust pack being present)
    if (payload_path) {
        COSE_CHECK(cose_trust_policy_builder_require_detached_payload_present(policy));
    } else {
        COSE_CHECK(cose_trust_policy_builder_require_detached_payload_absent(policy));
    }

#ifdef COSE_HAS_CERTIFICATES_PACK
    // Signing-key scope requirements (certificates pack)
    COSE_CHECK(cose_trust_policy_builder_and(policy));
    COSE_CHECK(cose_certificates_trust_policy_builder_require_x509_chain_trusted(policy));
    COSE_CHECK(cose_certificates_trust_policy_builder_require_signing_certificate_present(policy));
    COSE_CHECK(cose_certificates_trust_policy_builder_require_signing_certificate_thumbprint_present(policy));
#endif

#ifdef COSE_HAS_MST_PACK
    COSE_CHECK(cose_trust_policy_builder_and(policy));
    COSE_CHECK(cose_mst_trust_policy_builder_require_receipt_present(policy));
#endif

#ifdef COSE_HAS_AKV_PACK
    COSE_CHECK(cose_trust_policy_builder_and(policy));
    COSE_CHECK(cose_akv_trust_policy_builder_require_azure_key_vault_kid_allowed(policy));
#endif

    // 3) Compile + attach
    COSE_CHECK(cose_trust_policy_builder_compile(policy, &plan));
    COSE_CHECK(cose_validator_builder_with_compiled_trust_plan(builder, plan));

    // 4) Build validator
    COSE_CHECK(cose_validator_builder_build(builder, &validator));

    // 5) Validate
    COSE_CHECK(cose_validator_validate_bytes(
        validator,
        cose_bytes,
        cose_len,
        payload_bytes,
        payload_len,
        &result
    ));

    {
        bool ok = false;
        COSE_CHECK(cose_validation_result_is_success(result, &ok));
        if (ok) {
            printf("Validation successful\n");
        } else {
            char* msg = cose_validation_result_failure_message_utf8(result);
            printf("Validation failed: %s\n", msg ? msg : "(no message)");
            if (msg) cose_string_free(msg);
        }
    }

cleanup:
    if (result) cose_validation_result_free(result);
    if (validator) cose_validator_free(validator);
    if (plan) cose_compiled_trust_plan_free(plan);
    if (policy) cose_trust_policy_builder_free(policy);
    if (builder) cose_validator_builder_free(builder);

    free(payload_bytes);
    free(cose_bytes);

    return 0;
}
