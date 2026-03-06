// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file trust_policy_example.c
 * @brief Focused trust-policy authoring example for the COSE Sign1 C API.
 *
 * Demonstrates:
 *   1. TrustPolicyBuilder — compose per-requirement predicates with AND/OR
 *   2. TrustPlanBuilder   — select pack default plans, compile OR/AND
 *   3. Attach a compiled plan to a validator and validate dummy bytes
 */

#include <cose/sign1/validation.h>
#include <cose/sign1/trust.h>

#ifdef COSE_HAS_CERTIFICATES_PACK
#include <cose/sign1/extension_packs/certificates.h>
#endif

#ifdef COSE_HAS_MST_PACK
#include <cose/sign1/extension_packs/mst.h>
#endif

#ifdef COSE_HAS_AKV_PACK
#include <cose/sign1/extension_packs/azure_key_vault.h>
#endif

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

/* ========================================================================== */
/* Helpers                                                                    */
/* ========================================================================== */

static void print_last_error_and_free(void)
{
    char* err = cose_last_error_message_utf8();
    fprintf(stderr, "  Error: %s\n", err ? err : "(no error message)");
    if (err)
    {
        cose_string_free(err);
    }
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

/* ========================================================================== */
/* Approach 1: TrustPolicyBuilder — fine-grained predicates                   */
/* ========================================================================== */

static int demo_trust_policy_builder(void)
{
    printf("\n--- Approach 1: TrustPolicyBuilder ---\n");

    cose_sign1_validator_builder_t* builder = NULL;
    cose_sign1_trust_policy_builder_t* policy = NULL;
    cose_sign1_compiled_trust_plan_t* plan = NULL;
    cose_sign1_validator_t* validator = NULL;
    cose_sign1_validation_result_t* result = NULL;

    /* Dummy COSE_Sign1 bytes (intentionally invalid — we are demonstrating the
     * policy API, not producing a valid message). */
    const uint8_t dummy[] = { 0xD2, 0x84, 0x40, 0xA0, 0xF6, 0x40 };

    /* 1. Create builder and register packs. */
    COSE_CHECK(cose_sign1_validator_builder_new(&builder));

#ifdef COSE_HAS_CERTIFICATES_PACK
    COSE_CHECK(cose_sign1_validator_builder_with_certificates_pack(builder));
#endif
#ifdef COSE_HAS_MST_PACK
    COSE_CHECK(cose_sign1_validator_builder_with_mst_pack(builder));
#endif
#ifdef COSE_HAS_AKV_PACK
    COSE_CHECK(cose_sign1_validator_builder_with_akv_pack(builder));
#endif

    /* 2. Create policy builder from the configured packs. */
    COSE_CHECK(cose_sign1_trust_policy_builder_new_from_validator_builder(builder, &policy));

    /* ---- Message-scope predicates (always available) ---- */
    printf("  Require content-type == 'application/json'\n");
    COSE_CHECK(cose_sign1_trust_policy_builder_require_content_type_eq(
        policy, "application/json"));

    printf("  Require embedded payload (no detached)\n");
    COSE_CHECK(cose_sign1_trust_policy_builder_require_detached_payload_absent(policy));

    printf("  Require CWT claims present\n");
    COSE_CHECK(cose_sign1_trust_policy_builder_require_cwt_claims_present(policy));

    printf("  Require CWT iss == 'did:x509:sha256:abc::eku:1.3.6.1'\n");
    COSE_CHECK(cose_sign1_trust_policy_builder_require_cwt_iss_eq(
        policy, "did:x509:sha256:abc::eku:1.3.6.1"));

    printf("  Require CWT sub == 'contoso-release'\n");
    COSE_CHECK(cose_sign1_trust_policy_builder_require_cwt_sub_eq(
        policy, "contoso-release"));

#ifdef COSE_HAS_CERTIFICATES_PACK
    /* ---- Certificate-pack predicates (AND-composed) ---- */
    COSE_CHECK(cose_sign1_trust_policy_builder_and(policy));

    printf("  AND require X.509 chain trusted\n");
    COSE_CHECK(cose_sign1_certificates_trust_policy_builder_require_x509_chain_trusted(policy));

    printf("  AND require signing certificate present\n");
    COSE_CHECK(cose_sign1_certificates_trust_policy_builder_require_signing_certificate_present(policy));

    printf("  AND require signing cert thumbprint present\n");
    COSE_CHECK(cose_sign1_certificates_trust_policy_builder_require_signing_certificate_thumbprint_present(policy));

    printf("  AND require leaf subject == 'CN=Contoso Release'\n");
    COSE_CHECK(cose_sign1_certificates_trust_policy_builder_require_leaf_subject_eq(
        policy, "CN=Contoso Release"));

    printf("  AND require signing cert valid now (1700000000)\n");
    COSE_CHECK(cose_sign1_certificates_trust_policy_builder_require_signing_certificate_valid_at(
        policy, 1700000000));
#endif

#ifdef COSE_HAS_MST_PACK
    /* ---- MST-pack predicates (OR-composed — alternative trust path) ---- */
    COSE_CHECK(cose_sign1_trust_policy_builder_or(policy));

    printf("  OR require MST receipt present\n");
    COSE_CHECK(cose_sign1_mst_trust_policy_builder_require_receipt_present(policy));

    printf("     AND receipt trusted\n");
    COSE_CHECK(cose_sign1_mst_trust_policy_builder_require_receipt_trusted(policy));

    printf("     AND receipt issuer contains 'transparency.contoso.com'\n");
    COSE_CHECK(cose_sign1_mst_trust_policy_builder_require_receipt_issuer_contains(
        policy, "transparency.contoso.com"));
#endif

    /* 3. Compile the policy into a bundled plan. */
    printf("  Compiling policy...\n");
    COSE_CHECK(cose_sign1_trust_policy_builder_compile(policy, &plan));

    /* 4. Attach plan and build validator. */
    COSE_CHECK(cose_sign1_validator_builder_with_compiled_trust_plan(builder, plan));
    COSE_CHECK(cose_sign1_validator_builder_build(builder, &validator));

    /* 5. Validate (will fail on dummy bytes — that's expected). */
    printf("  Validating dummy bytes...\n");
    COSE_CHECK(cose_sign1_validator_validate_bytes(
        validator, dummy, sizeof(dummy), NULL, 0, &result));

    {
        bool ok = false;
        COSE_CHECK(cose_sign1_validation_result_is_success(result, &ok));
        if (ok)
        {
            printf("  Result: PASS\n");
        }
        else
        {
            char* msg = cose_sign1_validation_result_failure_message_utf8(result);
            printf("  Result: FAIL (expected): %s\n", msg ? msg : "(no message)");
            if (msg)
            {
                cose_string_free(msg);
            }
        }
    }

    printf("  TrustPolicyBuilder demo complete.\n");

cleanup:
    if (result) cose_sign1_validation_result_free(result);
    if (validator) cose_sign1_validator_free(validator);
    if (plan) cose_sign1_compiled_trust_plan_free(plan);
    if (policy) cose_sign1_trust_policy_builder_free(policy);
    if (builder) cose_sign1_validator_builder_free(builder);
    return 0;
}

/* ========================================================================== */
/* Approach 2: TrustPlanBuilder — compose pack default plans                  */
/* ========================================================================== */

static int demo_trust_plan_builder(void)
{
    printf("\n--- Approach 2: TrustPlanBuilder ---\n");

    cose_sign1_validator_builder_t* builder = NULL;
    cose_sign1_trust_plan_builder_t* plan_builder = NULL;
    cose_sign1_compiled_trust_plan_t* plan = NULL;
    cose_sign1_validator_t* validator = NULL;
    cose_sign1_validation_result_t* result = NULL;

    const uint8_t dummy[] = { 0xD2, 0x84, 0x40, 0xA0, 0xF6, 0x40 };

    /* 1. Builder + packs (same as above). */
    COSE_CHECK(cose_sign1_validator_builder_new(&builder));

#ifdef COSE_HAS_CERTIFICATES_PACK
    COSE_CHECK(cose_sign1_validator_builder_with_certificates_pack(builder));
#endif
#ifdef COSE_HAS_MST_PACK
    COSE_CHECK(cose_sign1_validator_builder_with_mst_pack(builder));
#endif

    /* 2. Create plan builder from the configured packs. */
    COSE_CHECK(cose_sign1_trust_plan_builder_new_from_validator_builder(builder, &plan_builder));

    /* Inspect registered packs. */
    size_t count = 0;
    COSE_CHECK(cose_sign1_trust_plan_builder_pack_count(plan_builder, &count));
    printf("  Registered packs: %zu\n", count);

    for (size_t i = 0; i < count; i++)
    {
        char* name = cose_sign1_trust_plan_builder_pack_name_utf8(plan_builder, i);
        bool has_default = false;
        COSE_CHECK(cose_sign1_trust_plan_builder_pack_has_default_plan(
            plan_builder, i, &has_default));
        printf("    [%zu] %s  default=%s\n",
               i, name ? name : "(null)", has_default ? "yes" : "no");
        if (name)
        {
            cose_string_free(name);
        }
    }

    /* 3. Select all pack default plans and compile as OR. */
    COSE_CHECK(cose_sign1_trust_plan_builder_add_all_pack_default_plans(plan_builder));
    printf("  Compiling as OR (any pack may satisfy)...\n");
    COSE_CHECK(cose_sign1_trust_plan_builder_compile_or(plan_builder, &plan));

    /* 4. Attach and validate. */
    COSE_CHECK(cose_sign1_validator_builder_with_compiled_trust_plan(builder, plan));
    COSE_CHECK(cose_sign1_validator_builder_build(builder, &validator));

    printf("  Validating dummy bytes...\n");
    COSE_CHECK(cose_sign1_validator_validate_bytes(
        validator, dummy, sizeof(dummy), NULL, 0, &result));

    {
        bool ok = false;
        COSE_CHECK(cose_sign1_validation_result_is_success(result, &ok));
        printf("  Result: %s\n", ok ? "PASS" : "FAIL (expected for dummy data)");
    }

    printf("  TrustPlanBuilder demo complete.\n");

cleanup:
    if (result) cose_sign1_validation_result_free(result);
    if (validator) cose_sign1_validator_free(validator);
    if (plan) cose_sign1_compiled_trust_plan_free(plan);
    if (plan_builder) cose_sign1_trust_plan_builder_free(plan_builder);
    if (builder) cose_sign1_validator_builder_free(builder);
    return 0;
}

/* ========================================================================== */
/* Main                                                                       */
/* ========================================================================== */

int main(void)
{
    printf("========================================\n");
    printf(" Trust Policy Authoring Example\n");
    printf("========================================\n");

    demo_trust_policy_builder();
    demo_trust_plan_builder();

    printf("\n========================================\n");
    printf(" Done.\n");
    printf("========================================\n");
    return 0;
}
