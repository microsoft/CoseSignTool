// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <gtest/gtest.h>

extern "C" {
#include <cose/cose_sign1.h>
#include <cose/cose_trust.h>

#ifdef COSE_HAS_CERTIFICATES_PACK
#include <cose/cose_certificates.h>
#endif

#ifdef COSE_HAS_MST_PACK
#include <cose/cose_mst.h>
#endif
}

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <string>
#include <vector>

#ifndef COSE_TESTDATA_V1_DIR
#define COSE_TESTDATA_V1_DIR ""
#endif

#ifndef COSE_MST_JWKS_PATH
#define COSE_MST_JWKS_PATH ""
#endif

static std::string take_last_error() {
    char* err = cose_last_error_message_utf8();
    std::string out = err ? err : "(no error message)";
    if (err) cose_string_free(err);
    return out;
}

static void assert_ok(cose_status_t st, const char* call) {
    ASSERT_EQ(st, COSE_OK) << call << ": " << take_last_error();
}

static void assert_not_ok(cose_status_t st, const char* call) {
    ASSERT_NE(st, COSE_OK) << "expected failure for " << call;
}

static std::vector<uint8_t> read_file_bytes(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("failed to open file: " + path);
    }

    f.seekg(0, std::ios::end);
    auto size = f.tellg();
    if (size < 0) {
        throw std::runtime_error("failed to stat file: " + path);
    }

    f.seekg(0, std::ios::beg);
    std::vector<uint8_t> out(static_cast<size_t>(size));
    if (!out.empty()) {
        f.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
        if (!f) {
            throw std::runtime_error("failed to read file: " + path);
        }
    }

    return out;
}

static std::string join_path2(const std::string& a, const std::string& b) {
    if (a.empty()) return b;
    const char last = a.back();
    if (last == '/' || last == '\\') return a + b;
    return a + "/" + b;
}

TEST(RealWorldTrustPlansC, CompileFailsWhenRequiredPackMissing) {
#ifndef COSE_HAS_TRUST_PACK
    GTEST_SKIP() << "trust pack not available";
#else
#ifndef COSE_HAS_CERTIFICATES_PACK
    GTEST_SKIP() << "COSE_HAS_CERTIFICATES_PACK not enabled";
#else
    cose_validator_builder_t* builder = nullptr;
    cose_trust_policy_builder_t* policy = nullptr;
    cose_compiled_trust_plan_t* plan = nullptr;

    assert_ok(cose_validator_builder_new(&builder), "cose_validator_builder_new");
    assert_ok(
        cose_trust_policy_builder_new_from_validator_builder(builder, &policy),
        "cose_trust_policy_builder_new_from_validator_builder");

    // Certificates pack is linked, but NOT configured on the builder.
    // Compiling should fail because no pack will produce the fact.
    assert_ok(
        cose_certificates_trust_policy_builder_require_x509_chain_trusted(policy),
        "cose_certificates_trust_policy_builder_require_x509_chain_trusted");

    cose_status_t st = cose_trust_policy_builder_compile(policy, &plan);
    assert_not_ok(st, "cose_trust_policy_builder_compile");

    cose_trust_policy_builder_free(policy);
    cose_validator_builder_free(builder);
#endif
#endif
}

TEST(RealWorldTrustPlansC, CompileSucceedsWhenRequiredPackPresent) {
#ifndef COSE_HAS_TRUST_PACK
    GTEST_SKIP() << "trust pack not available";
#else
#ifndef COSE_HAS_CERTIFICATES_PACK
    GTEST_SKIP() << "COSE_HAS_CERTIFICATES_PACK not enabled";
#else
    cose_validator_builder_t* builder = nullptr;
    cose_trust_policy_builder_t* policy = nullptr;
    cose_compiled_trust_plan_t* plan = nullptr;
    cose_validator_t* validator = nullptr;

    assert_ok(cose_validator_builder_new(&builder), "cose_validator_builder_new");
    assert_ok(cose_validator_builder_with_certificates_pack(builder), "cose_validator_builder_with_certificates_pack");

    assert_ok(
        cose_trust_policy_builder_new_from_validator_builder(builder, &policy),
        "cose_trust_policy_builder_new_from_validator_builder");

    assert_ok(
        cose_certificates_trust_policy_builder_require_x509_chain_trusted(policy),
        "cose_certificates_trust_policy_builder_require_x509_chain_trusted");

    assert_ok(cose_trust_policy_builder_compile(policy, &plan), "cose_trust_policy_builder_compile");
    assert_ok(
        cose_validator_builder_with_compiled_trust_plan(builder, plan),
        "cose_validator_builder_with_compiled_trust_plan");

    assert_ok(cose_validator_builder_build(builder, &validator), "cose_validator_builder_build");

    cose_validator_free(validator);
    cose_compiled_trust_plan_free(plan);
    cose_trust_policy_builder_free(policy);
    cose_validator_builder_free(builder);
#endif
#endif
}

TEST(RealWorldTrustPlansC, RealV1PolicyCanGateOnCertificateFacts) {
#ifndef COSE_HAS_TRUST_PACK
    GTEST_SKIP() << "trust pack not available";
#else
#ifndef COSE_HAS_CERTIFICATES_PACK
    GTEST_SKIP() << "COSE_HAS_CERTIFICATES_PACK not enabled";
#else
    cose_validator_builder_t* builder = nullptr;
    cose_trust_policy_builder_t* policy = nullptr;
    cose_compiled_trust_plan_t* plan = nullptr;

    assert_ok(cose_validator_builder_new(&builder), "cose_validator_builder_new");
    assert_ok(cose_validator_builder_with_certificates_pack(builder), "cose_validator_builder_with_certificates_pack");

    assert_ok(
        cose_trust_policy_builder_new_from_validator_builder(builder, &policy),
        "cose_trust_policy_builder_new_from_validator_builder");

    assert_ok(
        cose_certificates_trust_policy_builder_require_signing_certificate_present(policy),
        "cose_certificates_trust_policy_builder_require_signing_certificate_present");

    assert_ok(cose_trust_policy_builder_and(policy), "cose_trust_policy_builder_and");

    assert_ok(
        cose_certificates_trust_policy_builder_require_not_pqc_algorithm_or_missing(policy),
        "cose_certificates_trust_policy_builder_require_not_pqc_algorithm_or_missing");

    assert_ok(cose_trust_policy_builder_compile(policy, &plan), "cose_trust_policy_builder_compile");

    cose_compiled_trust_plan_free(plan);
    cose_trust_policy_builder_free(policy);
    cose_validator_builder_free(builder);
#endif
#endif
}

TEST(RealWorldTrustPlansC, RealScittPolicyCanRequireCwtClaimsAndMstReceiptTrustedFromIssuer) {
#ifndef COSE_HAS_TRUST_PACK
    GTEST_SKIP() << "trust pack not available";
#else
#ifndef COSE_HAS_MST_PACK
    GTEST_SKIP() << "COSE_HAS_MST_PACK not enabled";
#else
    if (std::string(COSE_MST_JWKS_PATH).empty()) {
        FAIL() << "COSE_MST_JWKS_PATH not set";
    }

    cose_validator_builder_t* builder = nullptr;
    cose_trust_policy_builder_t* policy = nullptr;
    cose_compiled_trust_plan_t* plan = nullptr;

    assert_ok(cose_validator_builder_new(&builder), "cose_validator_builder_new");

    const auto jwks_json = read_file_bytes(COSE_MST_JWKS_PATH);
    std::string jwks_str(reinterpret_cast<const char*>(jwks_json.data()), jwks_json.size());

    cose_mst_trust_options_t mst_opts;
    mst_opts.allow_network = false;
    mst_opts.offline_jwks_json = jwks_str.c_str();
    mst_opts.jwks_api_version = nullptr;

    assert_ok(
        cose_validator_builder_with_mst_pack_ex(builder, &mst_opts),
        "cose_validator_builder_with_mst_pack_ex");

#ifdef COSE_HAS_CERTIFICATES_PACK
    cose_certificate_trust_options_t cert_opts;
    cert_opts.trust_embedded_chain_as_trusted = true;
    cert_opts.identity_pinning_enabled = false;
    cert_opts.allowed_thumbprints = nullptr;
    cert_opts.pqc_algorithm_oids = nullptr;

    assert_ok(
        cose_validator_builder_with_certificates_pack_ex(builder, &cert_opts),
        "cose_validator_builder_with_certificates_pack_ex");
#endif

    assert_ok(
        cose_trust_policy_builder_new_from_validator_builder(builder, &policy),
        "cose_trust_policy_builder_new_from_validator_builder");

    assert_ok(
        cose_trust_policy_builder_require_cwt_claims_present(policy),
        "cose_trust_policy_builder_require_cwt_claims_present");

    assert_ok(cose_trust_policy_builder_and(policy), "cose_trust_policy_builder_and");

    assert_ok(
        cose_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains(
            policy,
            "confidential-ledger.azure.com"),
        "cose_mst_trust_policy_builder_require_receipt_trusted_from_issuer_contains");

    assert_ok(cose_trust_policy_builder_compile(policy, &plan), "cose_trust_policy_builder_compile");

    cose_compiled_trust_plan_free(plan);
    cose_trust_policy_builder_free(policy);
    cose_validator_builder_free(builder);
#endif
#endif
}

TEST(RealWorldTrustPlansC, RealV1PolicyCanValidateWithMstOnlyBypassingPrimarySignature) {
#ifndef COSE_HAS_TRUST_PACK
    GTEST_SKIP() << "trust pack not available";
#else
#ifndef COSE_HAS_MST_PACK
    GTEST_SKIP() << "COSE_HAS_MST_PACK not enabled";
#else
    if (std::string(COSE_TESTDATA_V1_DIR).empty()) {
        FAIL() << "COSE_TESTDATA_V1_DIR not set";
    }

    if (std::string(COSE_MST_JWKS_PATH).empty()) {
        FAIL() << "COSE_MST_JWKS_PATH not set";
    }

    cose_validator_builder_t* builder = nullptr;
    cose_trust_plan_builder_t* plan_builder = nullptr;
    cose_compiled_trust_plan_t* plan = nullptr;
    cose_validator_t* validator = nullptr;
    cose_validation_result_t* result = nullptr;

    assert_ok(cose_validator_builder_new(&builder), "cose_validator_builder_new");

    const auto jwks_json = read_file_bytes(COSE_MST_JWKS_PATH);
    std::string jwks_str(reinterpret_cast<const char*>(jwks_json.data()), jwks_json.size());

    cose_mst_trust_options_t mst_opts;
    mst_opts.allow_network = false;
    mst_opts.offline_jwks_json = jwks_str.c_str();
    mst_opts.jwks_api_version = nullptr;

    assert_ok(
        cose_validator_builder_with_mst_pack_ex(builder, &mst_opts),
        "cose_validator_builder_with_mst_pack_ex");

    assert_ok(
        cose_trust_plan_builder_new_from_validator_builder(builder, &plan_builder),
        "cose_trust_plan_builder_new_from_validator_builder");

    assert_ok(
        cose_trust_plan_builder_add_all_pack_default_plans(plan_builder),
        "cose_trust_plan_builder_add_all_pack_default_plans");

    assert_ok(
        cose_trust_plan_builder_compile_and(plan_builder, &plan),
        "cose_trust_plan_builder_compile_and");

    assert_ok(
        cose_validator_builder_with_compiled_trust_plan(builder, plan),
        "cose_validator_builder_with_compiled_trust_plan");

    assert_ok(cose_validator_builder_build(builder, &validator), "cose_validator_builder_build");

    for (const auto* file : {"2ts-statement.scitt", "1ts-statement.scitt"}) {
        const auto path = join_path2(COSE_TESTDATA_V1_DIR, file);
        const auto cose_bytes = read_file_bytes(path);

        assert_ok(
            cose_validator_validate_bytes(
                validator,
                cose_bytes.data(),
                cose_bytes.size(),
                nullptr,
                0,
                &result),
            "cose_validator_validate_bytes");

        bool ok = false;
        assert_ok(cose_validation_result_is_success(result, &ok), "cose_validation_result_is_success");
        ASSERT_TRUE(ok) << "expected success for " << file;

        cose_validation_result_free(result);
        result = nullptr;
    }

    cose_validator_free(validator);
    cose_compiled_trust_plan_free(plan);
    cose_trust_plan_builder_free(plan_builder);
    cose_validator_builder_free(builder);
#endif
#endif
}
