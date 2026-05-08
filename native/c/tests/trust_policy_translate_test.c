/*
 * Copyright (c) Microsoft Corporation.
 * Licensed under the MIT License.
 *
 * Trust-policy translation smoke test (C consumer).
 *
 * Exercises the C ABI of cose_sign1_trust_policy_spec_ffi end-to-end:
 *  1. Translate a minimal .coseTrustPolicy.json document.
 *  2. Inspect diagnostics on a deliberately-malformed document.
 *  3. Bind a parameter map, then compile to a trust plan.
 *
 * Returns 0 on success, non-zero on any failure (a fprintf describes which
 * step failed). All handles are released regardless of outcome.
 */

#include <cose/sign1/trust_policy.h>
#include <cose/sign1/validation.h>

#include <stdio.h>
#include <string.h>

#define CHECK(cond, msg) \
    do { \
        if (!(cond)) { \
            fprintf(stderr, "FAIL: %s\n", (msg)); \
            return 1; \
        } \
    } while (0)

static int test_translate_success(void) {
    const char* doc =
        "{\n"
        "  \"frontend\": \"cose-tp-json/v1\",\n"
        "  \"message\": { \"allow_all\": true }\n"
        "}";

    cose_sign1_trust_policy_translation_result_t* result = NULL;
    cose_status_t st = cose_sign1_trust_policy_translate_json(
        (const uint8_t*)doc, strlen(doc), &result);
    CHECK(st == COSE_OK, "translate_json (minimal) status");
    CHECK(result != NULL, "translate_json (minimal) result handle");
    CHECK(cose_sign1_trust_policy_result_is_success(result) == 1,
          "translate_json (minimal) is_success");
    CHECK(cose_sign1_trust_policy_result_diagnostic_count(result) == 0,
          "translate_json (minimal) diagnostic count");

    cose_sign1_trust_policy_spec_t* spec =
        cose_sign1_trust_policy_result_spec(result);
    CHECK(spec != NULL, "result_spec on minimal");
    CHECK(cose_sign1_trust_policy_spec_has_parameters(spec) == 0,
          "spec_has_parameters on minimal");

    cose_sign1_trust_policy_compiled_plan_t* plan = NULL;
    st = cose_sign1_trust_policy_spec_compile(spec, &plan);
    CHECK(st == COSE_OK, "compile (minimal) status");
    CHECK(plan != NULL, "compile (minimal) plan handle");

    cose_sign1_trust_policy_compiled_plan_free(plan);
    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
    return 0;
}

static int test_translate_parse_error(void) {
    const char* doc = "{ this is not json";

    cose_sign1_trust_policy_translation_result_t* result = NULL;
    cose_status_t st = cose_sign1_trust_policy_translate_json(
        (const uint8_t*)doc, strlen(doc), &result);
    CHECK(st == COSE_OK, "translate_json (broken) status");
    CHECK(result != NULL, "translate_json (broken) result handle");
    CHECK(cose_sign1_trust_policy_result_is_success(result) == 0,
          "translate_json (broken) is_success");

    size_t count = cose_sign1_trust_policy_result_diagnostic_count(result);
    CHECK(count >= 1, "broken doc must produce at least one diagnostic");

    const cose_sign1_trust_policy_diagnostic_t* diag =
        cose_sign1_trust_policy_result_diagnostic_at(result, 0);
    CHECK(diag != NULL, "diagnostic_at(0) on broken doc");

    uint8_t severity = 99;
    const uint8_t* code_ptr = NULL;
    size_t code_len = 0;
    cose_sign1_trust_policy_diagnostic_read(
        diag, &severity, &code_ptr, &code_len, NULL, NULL, NULL, NULL);
    CHECK(severity == COSE_TP_SEVERITY_ERROR,
          "broken doc diagnostic severity must be ERROR");
    CHECK(code_ptr != NULL && code_len == 6,
          "broken doc diagnostic code must be 6 bytes");
    CHECK(memcmp(code_ptr, "TPX001", 6) == 0,
          "broken doc diagnostic code must be TPX001");

    /* Out-of-bounds index returns null (defensive). */
    CHECK(cose_sign1_trust_policy_result_diagnostic_at(result, 9999) == NULL,
          "diagnostic_at out-of-bounds returns NULL");

    /* Spec accessor returns null when result is unsuccessful. */
    CHECK(cose_sign1_trust_policy_result_spec(result) == NULL,
          "result_spec on unsuccessful result");

    cose_sign1_trust_policy_result_free(result);
    return 0;
}

static int test_bind_and_compile(void) {
    const char* doc =
        "{\n"
        "  \"frontend\": \"cose-tp-json/v1\",\n"
        "  \"primary_signing_key\": {\n"
        "    \"fact\": \"x509-cert-identity/v1\",\n"
        "    \"predicate\": { \"thumbprint\": "
        "{\"$param\": \"tp\", \"default\": \"abc\"} }\n"
        "  }\n"
        "}";

    cose_sign1_trust_policy_translation_result_t* result = NULL;
    CHECK(cose_sign1_trust_policy_translate_json(
              (const uint8_t*)doc, strlen(doc), &result) == COSE_OK,
          "translate_json (param doc) status");
    CHECK(cose_sign1_trust_policy_result_is_success(result) == 1,
          "translate_json (param doc) is_success");

    cose_sign1_trust_policy_spec_t* spec =
        cose_sign1_trust_policy_result_spec(result);
    CHECK(spec != NULL, "result_spec on param doc");
    CHECK(cose_sign1_trust_policy_spec_has_parameters(spec) == 1,
          "spec_has_parameters on param doc");

    const char* params = "{\"tp\": \"my-thumbprint\"}";
    cose_sign1_trust_policy_translation_result_t* bind_result = NULL;
    CHECK(cose_sign1_trust_policy_spec_bind(
              spec, (const uint8_t*)params, strlen(params),
              &bind_result) == COSE_OK,
          "spec_bind status");
    CHECK(cose_sign1_trust_policy_result_is_success(bind_result) == 1,
          "spec_bind is_success");

    cose_sign1_trust_policy_spec_t* bound_spec =
        cose_sign1_trust_policy_result_spec(bind_result);
    CHECK(bound_spec != NULL, "result_spec after bind");
    CHECK(cose_sign1_trust_policy_spec_has_parameters(bound_spec) == 0,
          "post-bind spec must be parameter-free");

    cose_sign1_trust_policy_compiled_plan_t* plan = NULL;
    CHECK(cose_sign1_trust_policy_spec_compile(bound_spec, &plan) == COSE_OK,
          "compile bound spec status");
    CHECK(plan != NULL, "compile bound spec plan handle");

    cose_sign1_trust_policy_compiled_plan_free(plan);
    cose_sign1_trust_policy_spec_free(bound_spec);
    cose_sign1_trust_policy_result_free(bind_result);
    cose_sign1_trust_policy_spec_free(spec);
    cose_sign1_trust_policy_result_free(result);
    return 0;
}

static int test_frontend_id(void) {
    const char* id = cose_sign1_trust_policy_frontend_id();
    CHECK(id != NULL, "frontend_id must not be NULL");
    CHECK(strcmp(id, "cose-tp-json/v1") == 0,
          "frontend_id must equal canonical value");
    return 0;
}

static int test_null_tolerance(void) {
    /* Every accessor and free function tolerates NULL. */
    CHECK(cose_sign1_trust_policy_result_diagnostic_count(NULL) == 0,
          "diagnostic_count(NULL) returns 0");
    CHECK(cose_sign1_trust_policy_result_diagnostic_at(NULL, 0) == NULL,
          "diagnostic_at(NULL) returns NULL");
    CHECK(cose_sign1_trust_policy_result_is_success(NULL) == 0,
          "is_success(NULL) returns 0");
    CHECK(cose_sign1_trust_policy_result_spec(NULL) == NULL,
          "result_spec(NULL) returns NULL");
    CHECK(cose_sign1_trust_policy_spec_has_parameters(NULL) == 0,
          "spec_has_parameters(NULL) returns 0");

    /* Free NULL is a no-op. */
    cose_sign1_trust_policy_result_free(NULL);
    cose_sign1_trust_policy_spec_free(NULL);
    cose_sign1_trust_policy_compiled_plan_free(NULL);

    /* diagnostic_read on a null handle does nothing — no crash. */
    cose_sign1_trust_policy_diagnostic_read(
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    return 0;
}

int main(void) {
    printf("COSE Trust-Policy C smoke test\n");

    if (test_translate_success() != 0) return 1;
    printf("  [ok] translate-success\n");

    if (test_translate_parse_error() != 0) return 1;
    printf("  [ok] translate-parse-error + diagnostic introspection\n");

    if (test_bind_and_compile() != 0) return 1;
    printf("  [ok] bind + compile\n");

    if (test_frontend_id() != 0) return 1;
    printf("  [ok] frontend_id\n");

    if (test_null_tolerance() != 0) return 1;
    printf("  [ok] null-tolerance\n");

    printf("All trust-policy smoke checks passed.\n");
    return 0;
}
