// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cose/cose_sign1.h>
#include <cose/cose_certificates.h>
#include <cose/cose_mst.h>
#include <cose/cose_azure_key_vault.h>
#include <cose/cose_trust.h>
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

#ifdef COSE_HAS_MST_PACK
    // Add MST pack (so MST receipt facts can be produced during validation)
    status = cose_validator_builder_with_mst_pack(builder);
    if (status != COSE_OK) {
        fprintf(stderr, "Failed to add MST pack: %d\n", status);
        char* err = cose_last_error_message_utf8();
        if (err) {
            fprintf(stderr, "Error: %s\n", err);
            cose_string_free(err);
        }
        cose_validator_builder_free(builder);
        return 1;
    }
    printf("✓ MST pack added\n");
#endif

#ifdef COSE_HAS_AKV_PACK
    // Add AKV pack (so AKV facts can be produced during validation)
    status = cose_validator_builder_with_akv_pack(builder);
    if (status != COSE_OK) {
        fprintf(stderr, "Failed to add AKV pack: %d\n", status);
        char* err = cose_last_error_message_utf8();
        if (err) {
            fprintf(stderr, "Error: %s\n", err);
            cose_string_free(err);
        }
        cose_validator_builder_free(builder);
        return 1;
    }
    printf("✓ AKV pack added\n");
#endif
#ifdef COSE_HAS_TRUST_PACK
    // Trust-plan authoring: build a bundled plan from pack defaults and attach it.
    {
        cose_trust_plan_builder_t* plan_builder = NULL;
        status = cose_trust_plan_builder_new_from_validator_builder(builder, &plan_builder);
        if (status != COSE_OK || !plan_builder) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to create trust plan builder: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_validator_builder_free(builder);
            return 1;
        }

        // Pack enumeration helpers (for diagnostics / UI use-cases).
        {
            size_t pack_count = 0;
            status = cose_trust_plan_builder_pack_count(plan_builder, &pack_count);
            if (status != COSE_OK) {
                char* err = cose_last_error_message_utf8();
                fprintf(stderr, "Failed to get pack count: %s\n", err ? err : "(no error)");
                if (err) cose_string_free(err);
                cose_trust_plan_builder_free(plan_builder);
                cose_validator_builder_free(builder);
                return 1;
            }

            for (size_t i = 0; i < pack_count; i++) {
                char* name = cose_trust_plan_builder_pack_name_utf8(plan_builder, i);
                if (!name) {
                    char* err = cose_last_error_message_utf8();
                    fprintf(stderr, "Failed to get pack name: %s\n", err ? err : "(no error)");
                    if (err) cose_string_free(err);
                    cose_trust_plan_builder_free(plan_builder);
                    cose_validator_builder_free(builder);
                    return 1;
                }

                bool has_default = false;
                status = cose_trust_plan_builder_pack_has_default_plan(plan_builder, i, &has_default);
                if (status != COSE_OK) {
                    char* err = cose_last_error_message_utf8();
                    fprintf(stderr, "Failed to query pack default plan: %s\n", err ? err : "(no error)");
                    if (err) cose_string_free(err);
                    cose_string_free(name);
                    cose_trust_plan_builder_free(plan_builder);
                    cose_validator_builder_free(builder);
                    return 1;
                }

                printf("  - Pack[%zu] %s (default plan: %s)\n", i, name, has_default ? "yes" : "no");
                cose_string_free(name);
            }
        }

        status = cose_trust_plan_builder_add_all_pack_default_plans(plan_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add default plans: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_plan_builder_free(plan_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        cose_compiled_trust_plan_t* plan = NULL;
        status = cose_trust_plan_builder_compile_or(plan_builder, &plan);
        cose_trust_plan_builder_free(plan_builder);
        if (status != COSE_OK || !plan) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to compile trust plan: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_validator_builder_with_compiled_trust_plan(builder, plan);
        cose_compiled_trust_plan_free(plan);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to attach trust plan: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_validator_builder_free(builder);
            return 1;
        }

        printf("✓ Compiled trust plan attached\n");
    }

    // Trust-policy authoring: compile a small custom policy and attach it (overrides prior plan).
    {
        cose_trust_policy_builder_t* policy_builder = NULL;
        status = cose_trust_policy_builder_new_from_validator_builder(builder, &policy_builder);
        if (status != COSE_OK || !policy_builder) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to create trust policy builder: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_trust_policy_builder_require_detached_payload_absent(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add policy rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

#ifdef COSE_HAS_CERTIFICATES_PACK
        // Pack-specific trust-policy helpers (certificates / X.509 predicates)
        status = cose_certificates_trust_policy_builder_require_x509_chain_trusted(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add x509-chain-trusted rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_x509_chain_built(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add x509-chain-built rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_x509_chain_element_count_eq(policy_builder, 1);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add x509-chain-element-count rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_x509_chain_status_flags_eq(policy_builder, 0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add x509-chain-status-flags rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_leaf_chain_thumbprint_present(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add leaf-thumbprint-present rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_signing_certificate_present(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add signing-cert-present rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_leaf_subject_eq(policy_builder, "CN=example");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add leaf-subject-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_issuer_subject_eq(policy_builder, "CN=issuer.example");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add issuer-subject-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_signing_certificate_subject_issuer_matches_leaf_chain_element(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add signing-cert-matches-leaf rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_leaf_issuer_is_next_chain_subject_optional(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add issuer-chaining-optional rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_signing_certificate_thumbprint_eq(policy_builder, "ABCD1234");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add signing-cert-thumbprint-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_signing_certificate_thumbprint_present(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add signing-cert-thumbprint-present rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_signing_certificate_subject_eq(policy_builder, "CN=example");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add signing-cert-subject-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_signing_certificate_issuer_eq(policy_builder, "CN=issuer.example");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add signing-cert-issuer-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_signing_certificate_serial_number_eq(policy_builder, "01");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add signing-cert-serial-number-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_signing_certificate_expired_at_or_before(policy_builder, 0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add signing-cert-expired rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_signing_certificate_valid_at(policy_builder, (int64_t)0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add signing-cert-valid-at rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_signing_certificate_not_before_le(policy_builder, (int64_t)0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add signing-cert-not-before-le rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_signing_certificate_not_before_ge(policy_builder, (int64_t)0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add signing-cert-not-before-ge rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_signing_certificate_not_after_le(policy_builder, (int64_t)0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add signing-cert-not-after-le rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_signing_certificate_not_after_ge(policy_builder, (int64_t)0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add signing-cert-not-after-ge rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_chain_element_subject_eq(policy_builder, (size_t)0, "CN=example");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add chain-element[0]-subject-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_chain_element_issuer_eq(policy_builder, (size_t)0, "CN=issuer.example");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add chain-element[0]-issuer-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_chain_element_thumbprint_present(policy_builder, (size_t)0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add chain-element[0]-thumbprint-present rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_chain_element_thumbprint_eq(policy_builder, (size_t)0, "ABCD1234");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add chain-element[0]-thumbprint-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_chain_element_valid_at(policy_builder, (size_t)0, (int64_t)0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add chain-element[0]-valid-at rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_chain_element_not_before_le(policy_builder, (size_t)0, (int64_t)0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add chain-element[0]-not-before-le rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_chain_element_not_before_ge(policy_builder, (size_t)0, (int64_t)0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add chain-element[0]-not-before-ge rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_chain_element_not_after_le(policy_builder, (size_t)0, (int64_t)0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add chain-element[0]-not-after-le rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_chain_element_not_after_ge(policy_builder, (size_t)0, (int64_t)0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add chain-element[0]-not-after-ge rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_not_pqc_algorithm_or_missing(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add not-pqc-or-missing rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_thumbprint_eq(policy_builder, "ABCD1234");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add x509-public-key-algorithm-thumbprint-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_oid_eq(policy_builder, "1.2.840.113549.1.1.1");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add x509-public-key-algorithm-oid-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_is_not_pqc(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add x509-public-key-algorithm-not-pqc rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }
#endif

#ifdef COSE_HAS_MST_PACK
        // Pack-specific trust-policy helpers (MST receipt predicates)
        status = cose_mst_trust_policy_builder_require_receipt_present(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add MST receipt-present rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_mst_trust_policy_builder_require_receipt_not_present(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add MST receipt-not-present rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_mst_trust_policy_builder_require_receipt_signature_verified(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add MST receipt-signature-verified rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_mst_trust_policy_builder_require_receipt_signature_not_verified(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add MST receipt-signature-not-verified rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_mst_trust_policy_builder_require_receipt_issuer_contains(policy_builder, "microsoft");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add MST receipt-issuer-contains rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_mst_trust_policy_builder_require_receipt_issuer_eq(policy_builder, "issuer.example");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add MST receipt-issuer-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_mst_trust_policy_builder_require_receipt_kid_eq(policy_builder, "kid.example");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add MST receipt-kid-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_mst_trust_policy_builder_require_receipt_kid_contains(policy_builder, "kid");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add MST receipt-kid-contains rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_mst_trust_policy_builder_require_receipt_trusted(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add MST receipt-trusted rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_mst_trust_policy_builder_require_receipt_not_trusted(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add MST receipt-not-trusted rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(policy_builder, "microsoft");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add MST receipt-trusted-from-issuer-contains rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_mst_trust_policy_builder_require_receipt_statement_sha256_eq(
            policy_builder,
            "0000000000000000000000000000000000000000000000000000000000000000");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add MST receipt-statement-sha256-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_mst_trust_policy_builder_require_receipt_statement_coverage_eq(policy_builder, "coverage.example");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add MST receipt-statement-coverage-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_mst_trust_policy_builder_require_receipt_statement_coverage_contains(policy_builder, "example");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add MST receipt-statement-coverage-contains rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }
#endif

        status = cose_trust_policy_builder_require_cwt_claims_present(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add CWT claims-present rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_trust_policy_builder_require_cwt_iss_eq(policy_builder, "issuer.example");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add CWT iss-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_trust_policy_builder_require_cwt_claim_label_present(policy_builder, (int64_t)6);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add CWT claim label-present rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_trust_policy_builder_require_cwt_claim_label_i64_ge(policy_builder, (int64_t)6, (int64_t)123);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add CWT claim label i64-ge rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_trust_policy_builder_require_cwt_claim_label_bool_eq(policy_builder, (int64_t)6, true);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add CWT claim label bool-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_trust_policy_builder_require_cwt_claim_text_str_eq(policy_builder, "nonce", "abc");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add CWT claim text str-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_trust_policy_builder_require_cwt_claim_text_str_starts_with(policy_builder, "nonce", "a");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add CWT claim text starts-with rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_trust_policy_builder_require_cwt_claim_text_str_contains(policy_builder, "nonce", "b");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add CWT claim text contains rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

#ifdef COSE_HAS_AKV_PACK
        // Pack-specific policy helpers (AKV)
        status = cose_akv_trust_policy_builder_require_azure_key_vault_kid(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add AKV kid-detected rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_akv_trust_policy_builder_require_not_azure_key_vault_kid(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add AKV kid-not-detected rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_akv_trust_policy_builder_require_azure_key_vault_kid_allowed(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add AKV kid-allowed rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_akv_trust_policy_builder_require_azure_key_vault_kid_not_allowed(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add AKV kid-not-allowed rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }
#endif

        status = cose_trust_policy_builder_require_cwt_claim_label_str_starts_with(policy_builder, (int64_t)1000, "a");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add CWT claim label starts-with rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_trust_policy_builder_require_cwt_claim_label_str_contains(policy_builder, (int64_t)1000, "b");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add CWT claim label contains rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_trust_policy_builder_require_cwt_claim_label_str_eq(policy_builder, (int64_t)1000, "exact.example");
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add CWT claim label str-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_trust_policy_builder_require_cwt_claim_text_i64_le(policy_builder, "nonce", (int64_t)0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add CWT claim text i64-le rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_trust_policy_builder_require_cwt_claim_text_i64_eq(policy_builder, "nonce", (int64_t)0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add CWT claim text i64-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_trust_policy_builder_require_cwt_claim_text_bool_eq(policy_builder, "nonce", true);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add CWT claim text bool-eq rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_trust_policy_builder_require_cwt_exp_ge(policy_builder, 0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add CWT exp-ge rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_trust_policy_builder_require_cwt_iat_le(policy_builder, 0);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add CWT iat-le rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_trust_policy_builder_require_counter_signature_envelope_sig_structure_intact_or_missing(policy_builder);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to add counter-signature envelope-integrity rule: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_trust_policy_builder_free(policy_builder);
            cose_validator_builder_free(builder);
            return 1;
        }

        cose_compiled_trust_plan_t* plan = NULL;
        status = cose_trust_policy_builder_compile(policy_builder, &plan);
        cose_trust_policy_builder_free(policy_builder);
        if (status != COSE_OK || !plan) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to compile trust policy: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_validator_builder_free(builder);
            return 1;
        }

        status = cose_validator_builder_with_compiled_trust_plan(builder, plan);
        cose_compiled_trust_plan_free(plan);
        if (status != COSE_OK) {
            char* err = cose_last_error_message_utf8();
            fprintf(stderr, "Failed to attach trust policy: %s\n", err ? err : "(no error)");
            if (err) cose_string_free(err);
            cose_validator_builder_free(builder);
            return 1;
        }

        printf("✓ Custom trust policy compiled and attached\n");
    }
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
