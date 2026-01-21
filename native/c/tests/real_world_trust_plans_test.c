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

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef COSE_TESTDATA_V1_DIR
#define COSE_TESTDATA_V1_DIR ""
#endif

#ifndef COSE_MST_JWKS_PATH
#define COSE_MST_JWKS_PATH ""
#endif

static void fail(const char* msg) {
    fprintf(stderr, "FAIL: %s\n", msg);
    exit(1);
}

static void assert_status_ok(cose_status_t st, const char* call) {
    if (st == COSE_OK) return;

    fprintf(stderr, "FAILED: %s\n", call);
    char* err = cose_last_error_message_utf8();
    fprintf(stderr, "%s\n", err ? err : "(no error message)");
    if (err) cose_string_free(err);
    exit(1);
}

static void assert_status_not_ok(cose_status_t st, const char* call) {
    if (st != COSE_OK) return;

    fprintf(stderr, "EXPECTED FAILURE but got COSE_OK: %s\n", call);
    exit(1);
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

static char* join_path2(const char* a, const char* b) {
    size_t alen = strlen(a);
    size_t blen = strlen(b);

    const bool need_sep = (alen > 0 && a[alen - 1] != '/' && a[alen - 1] != '\\');
    size_t len = alen + (need_sep ? 1 : 0) + blen + 1;

    char* out = (char*)malloc(len);
    if (!out) return NULL;

    memcpy(out, a, alen);
    size_t pos = alen;
    if (need_sep) {
        out[pos++] = '/';
    }
    memcpy(out + pos, b, blen);
    out[pos + blen] = 0;
    return out;
}

static void test_compile_fails_when_required_pack_missing(void) {
#ifndef COSE_HAS_CERTIFICATES_PACK
    printf("SKIP: %s (COSE_HAS_CERTIFICATES_PACK not enabled)\n", __func__);
    return;
#else
    cose_validator_builder_t* builder = NULL;
    cose_trust_policy_builder_t* policy = NULL;
    cose_compiled_trust_plan_t* plan = NULL;

    assert_status_ok(cose_validator_builder_new(&builder), "cose_validator_builder_new");
    assert_status_ok(
        cose_trust_policy_builder_new_from_validator_builder(builder, &policy),
        "cose_trust_policy_builder_new_from_validator_builder"
    );

    // Certificates pack is linked, but NOT configured on the builder.
    // The require-call succeeds, but compiling should fail because no pack will produce the fact.
    assert_status_ok(
        cose_certificates_trust_policy_builder_require_x509_chain_trusted(policy),
        "cose_certificates_trust_policy_builder_require_x509_chain_trusted"
    );

    cose_status_t st = cose_trust_policy_builder_compile(policy, &plan);
    assert_status_not_ok(st, "cose_trust_policy_builder_compile");

    cose_trust_policy_builder_free(policy);
    cose_validator_builder_free(builder);
#endif
}

static void test_compile_succeeds_when_required_pack_present(void) {
#ifndef COSE_HAS_CERTIFICATES_PACK
    printf("SKIP: %s (COSE_HAS_CERTIFICATES_PACK not enabled)\n", __func__);
    return;
#else
    cose_validator_builder_t* builder = NULL;
    cose_trust_policy_builder_t* policy = NULL;
    cose_compiled_trust_plan_t* plan = NULL;
    cose_validator_t* validator = NULL;

    assert_status_ok(cose_validator_builder_new(&builder), "cose_validator_builder_new");
    assert_status_ok(
        cose_validator_builder_with_certificates_pack(builder),
        "cose_validator_builder_with_certificates_pack"
    );

    assert_status_ok(
        cose_trust_policy_builder_new_from_validator_builder(builder, &policy),
        "cose_trust_policy_builder_new_from_validator_builder"
    );

    assert_status_ok(
        cose_certificates_trust_policy_builder_require_x509_chain_trusted(policy),
        "cose_certificates_trust_policy_builder_require_x509_chain_trusted"
    );

    assert_status_ok(
        cose_trust_policy_builder_compile(policy, &plan),
        "cose_trust_policy_builder_compile"
    );

    assert_status_ok(
        cose_validator_builder_with_compiled_trust_plan(builder, plan),
        "cose_validator_builder_with_compiled_trust_plan"
    );

    assert_status_ok(
        cose_validator_builder_build(builder, &validator),
        "cose_validator_builder_build"
    );

    cose_validator_free(validator);
    cose_compiled_trust_plan_free(plan);
    cose_trust_policy_builder_free(policy);
    cose_validator_builder_free(builder);
#endif
}

static void test_real_v1_policy_can_gate_on_certificate_facts(void) {
#ifndef COSE_HAS_CERTIFICATES_PACK
    printf("SKIP: %s (COSE_HAS_CERTIFICATES_PACK not enabled)\n", __func__);
    return;
#else
    cose_validator_builder_t* builder = NULL;
    cose_trust_policy_builder_t* policy = NULL;
    cose_compiled_trust_plan_t* plan = NULL;

    assert_status_ok(cose_validator_builder_new(&builder), "cose_validator_builder_new");
    assert_status_ok(
        cose_validator_builder_with_certificates_pack(builder),
        "cose_validator_builder_with_certificates_pack"
    );

    assert_status_ok(
        cose_trust_policy_builder_new_from_validator_builder(builder, &policy),
        "cose_trust_policy_builder_new_from_validator_builder"
    );

    // Roughly matches: require_signing_certificate_present AND require_not_pqc_algorithm_or_missing
    assert_status_ok(
        cose_certificates_trust_policy_builder_require_signing_certificate_present(policy),
        "cose_certificates_trust_policy_builder_require_signing_certificate_present"
    );
    assert_status_ok(cose_trust_policy_builder_and(policy), "cose_trust_policy_builder_and");
    assert_status_ok(
        cose_certificates_trust_policy_builder_require_not_pqc_algorithm_or_missing(policy),
        "cose_certificates_trust_policy_builder_require_not_pqc_algorithm_or_missing"
    );

    assert_status_ok(
        cose_trust_policy_builder_compile(policy, &plan),
        "cose_trust_policy_builder_compile"
    );

    cose_compiled_trust_plan_free(plan);
    cose_trust_policy_builder_free(policy);
    cose_validator_builder_free(builder);
#endif
}

static void test_real_scitt_policy_can_require_cwt_claims_and_mst_receipt_trusted_from_issuer(void) {
#ifndef COSE_HAS_MST_PACK
    printf("SKIP: %s (COSE_HAS_MST_PACK not enabled)\n", __func__);
    return;
#else
    // Build/compile a policy that mirrors the Rust real-world policy shape (using only projected helpers).
    // Note: end-to-end validation of the SCITT vectors requires counter-signature-driven primary-signature bypass,
    // which is driven by the MST pack default trust plan; see the separate validation test below.
    cose_validator_builder_t* builder = NULL;
    cose_trust_policy_builder_t* policy = NULL;
    cose_compiled_trust_plan_t* plan = NULL;

    uint8_t* jwks_bytes = NULL;
    size_t jwks_len = 0;

    assert_status_ok(cose_validator_builder_new(&builder), "cose_validator_builder_new");

    // MST offline JWKS (deterministic)
    if (COSE_MST_JWKS_PATH[0] == 0) {
        fail("COSE_MST_JWKS_PATH not set");
    }
    if (!read_file_bytes(COSE_MST_JWKS_PATH, &jwks_bytes, &jwks_len)) {
        fail("failed to read MST JWKS json");
    }

    // Ensure null-terminated JSON string
    char* jwks_json = (char*)malloc(jwks_len + 1);
    if (!jwks_json) {
        fail("out of memory");
    }
    memcpy(jwks_json, jwks_bytes, jwks_len);
    jwks_json[jwks_len] = 0;

    cose_mst_trust_options_t mst_opts;
    mst_opts.allow_network = false;
    mst_opts.offline_jwks_json = jwks_json;
    mst_opts.jwks_api_version = NULL;

    assert_status_ok(
        cose_validator_builder_with_mst_pack_ex(builder, &mst_opts),
        "cose_validator_builder_with_mst_pack_ex"
    );

#ifdef COSE_HAS_CERTIFICATES_PACK
    // Mirror Rust tests: include certificates pack too.
    cose_certificate_trust_options_t cert_opts;
    cert_opts.trust_embedded_chain_as_trusted = true;
    cert_opts.identity_pinning_enabled = false;
    cert_opts.allowed_thumbprints = NULL;
    cert_opts.pqc_algorithm_oids = NULL;

    assert_status_ok(
        cose_validator_builder_with_certificates_pack_ex(builder, &cert_opts),
        "cose_validator_builder_with_certificates_pack_ex"
    );
#endif

    assert_status_ok(
        cose_trust_policy_builder_new_from_validator_builder(builder, &policy),
        "cose_trust_policy_builder_new_from_validator_builder"
    );

    assert_status_ok(
        cose_trust_policy_builder_require_cwt_claims_present(policy),
        "cose_trust_policy_builder_require_cwt_claims_present"
    );

    assert_status_ok(cose_trust_policy_builder_and(policy), "cose_trust_policy_builder_and");
    assert_status_ok(
        cose_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(
            policy,
            "confidential-ledger.azure.com"
        ),
        "cose_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains"
    );

    assert_status_ok(
        cose_trust_policy_builder_compile(policy, &plan),
        "cose_trust_policy_builder_compile"
    );

    cose_compiled_trust_plan_free(plan);
    cose_trust_policy_builder_free(policy);
    cose_validator_builder_free(builder);

    free(jwks_json);
    free(jwks_bytes);
#endif
}

static void test_real_v1_policy_can_validate_with_mst_only_by_bypassing_primary_signature(void) {
#ifndef COSE_HAS_MST_PACK
    printf("SKIP: %s (COSE_HAS_MST_PACK not enabled)\n", __func__);
    return;
#else
    cose_validator_builder_t* builder = NULL;
    cose_trust_plan_builder_t* plan_builder = NULL;
    cose_compiled_trust_plan_t* plan = NULL;
    cose_validator_t* validator = NULL;
    cose_validation_result_t* result = NULL;

    uint8_t* cose_bytes = NULL;
    size_t cose_len = 0;

    uint8_t* jwks_bytes = NULL;
    size_t jwks_len = 0;

    assert_status_ok(cose_validator_builder_new(&builder), "cose_validator_builder_new");

    if (!read_file_bytes(COSE_MST_JWKS_PATH, &jwks_bytes, &jwks_len)) {
        fail("failed to read MST JWKS json");
    }

    char* jwks_json = (char*)malloc(jwks_len + 1);
    if (!jwks_json) {
        fail("out of memory");
    }
    memcpy(jwks_json, jwks_bytes, jwks_len);
    jwks_json[jwks_len] = 0;

    cose_mst_trust_options_t mst_opts;
    mst_opts.allow_network = false;
    mst_opts.offline_jwks_json = jwks_json;
    mst_opts.jwks_api_version = NULL;

    assert_status_ok(
        cose_validator_builder_with_mst_pack_ex(builder, &mst_opts),
        "cose_validator_builder_with_mst_pack_ex"
    );

    // Use the MST pack default trust plan; this is the native analogue to Rust's TrustPlanBuilder MST-only policy,
    // and is expected to enable bypassing unsupported primary signature algorithms when countersignature evidence exists.
    assert_status_ok(
        cose_trust_plan_builder_new_from_validator_builder(builder, &plan_builder),
        "cose_trust_plan_builder_new_from_validator_builder"
    );
    assert_status_ok(
        cose_trust_plan_builder_add_all_pack_default_plans(plan_builder),
        "cose_trust_plan_builder_add_all_pack_default_plans"
    );
    assert_status_ok(
        cose_trust_plan_builder_compile_and(plan_builder, &plan),
        "cose_trust_plan_builder_compile_and"
    );

    assert_status_ok(
        cose_validator_builder_with_compiled_trust_plan(builder, plan),
        "cose_validator_builder_with_compiled_trust_plan"
    );
    assert_status_ok(
        cose_validator_builder_build(builder, &validator),
        "cose_validator_builder_build"
    );

    // Validate both v1 SCITT vectors.
    const char* files[] = {"2ts-statement.scitt", "1ts-statement.scitt"};
    for (size_t i = 0; i < 2; i++) {
        char* path = join_path2(COSE_TESTDATA_V1_DIR, files[i]);
        if (!path) {
            fail("out of memory");
        }
        if (!read_file_bytes(path, &cose_bytes, &cose_len)) {
            fprintf(stderr, "Failed to read test vector: %s\n", path);
            fail("missing test vector");
        }

        assert_status_ok(
            cose_validator_validate_bytes(validator, cose_bytes, cose_len, NULL, 0, &result),
            "cose_validator_validate_bytes"
        );

        bool ok = false;
        assert_status_ok(cose_validation_result_is_success(result, &ok), "cose_validation_result_is_success");
        if (!ok) {
            char* msg = cose_validation_result_failure_message_utf8(result);
            fprintf(stderr, "expected success but validation failed for %s: %s\n", files[i], msg ? msg : "(no message)");
            if (msg) cose_string_free(msg);
            exit(1);
        }

        cose_validation_result_free(result);
        result = NULL;
        free(cose_bytes);
        cose_bytes = NULL;
        free(path);
    }

    cose_validator_free(validator);
    cose_compiled_trust_plan_free(plan);
    cose_trust_plan_builder_free(plan_builder);
    cose_validator_builder_free(builder);

    free(jwks_json);
    free(jwks_bytes);
#endif
}

typedef void (*test_fn_t)(void);

typedef struct test_case_t {
    const char* name;
    test_fn_t fn;
} test_case_t;

static const test_case_t g_tests[] = {
    {"compile_fails_when_required_pack_missing", test_compile_fails_when_required_pack_missing},
    {"compile_succeeds_when_required_pack_present", test_compile_succeeds_when_required_pack_present},
    {"real_v1_policy_can_gate_on_certificate_facts", test_real_v1_policy_can_gate_on_certificate_facts},
    {"real_scitt_policy_can_require_cwt_claims_and_mst_receipt_trusted_from_issuer", test_real_scitt_policy_can_require_cwt_claims_and_mst_receipt_trusted_from_issuer},
    {"real_v1_policy_can_validate_with_mst_only_by_bypassing_primary_signature", test_real_v1_policy_can_validate_with_mst_only_by_bypassing_primary_signature},
};

static void usage(const char* argv0) {
    fprintf(stderr,
            "Usage:\n"
            "  %s [--list] [--test <name>]\n",
            argv0);
}

static void list_tests(void) {
    for (size_t i = 0; i < (sizeof(g_tests) / sizeof(g_tests[0])); i++) {
        printf("%s\n", g_tests[i].name);
    }
}

static int run_one(const char* name) {
    for (size_t i = 0; i < (sizeof(g_tests) / sizeof(g_tests[0])); i++) {
        if (strcmp(g_tests[i].name, name) == 0) {
            printf("RUN: %s\n", g_tests[i].name);
            g_tests[i].fn();
            printf("PASS: %s\n", g_tests[i].name);
            return 0;
        }
    }
    fprintf(stderr, "Unknown test: %s\n", name);
    return 2;
}

int main(int argc, char** argv) {
#ifndef COSE_HAS_TRUST_PACK
    // If trust pack isn't present, this test target should ideally be skipped at build time,
    // but keep a safe runtime no-op.
    printf("Skipping: trust pack not available\n");
    return 0;
#else
    if (argc == 2 && strcmp(argv[1], "--list") == 0) {
        list_tests();
        return 0;
    }

    if (argc == 3 && strcmp(argv[1], "--test") == 0) {
        return run_one(argv[2]);
    }

    if (argc != 1) {
        usage(argv[0]);
        return 2;
    }

    for (size_t i = 0; i < (sizeof(g_tests) / sizeof(g_tests[0])); i++) {
        int rc = run_one(g_tests[i].name);
        if (rc != 0) {
            return rc;
        }
    }

    printf("OK\n");
    return 0;
#endif
}
