// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cose/trust.hpp>

#ifdef COSE_HAS_CERTIFICATES_PACK
#include <cose/certificates.hpp>
#endif

#ifdef COSE_HAS_MST_PACK
#include <cose/mst.hpp>
#endif

#include <cstdint>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#ifndef COSE_TESTDATA_V1_DIR
#define COSE_TESTDATA_V1_DIR ""
#endif

#ifndef COSE_MST_JWKS_PATH
#define COSE_MST_JWKS_PATH ""
#endif

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

static void test_compile_fails_when_required_pack_missing() {
#ifndef COSE_HAS_CERTIFICATES_PACK
    std::cout << "SKIP: " << __func__ << " (COSE_HAS_CERTIFICATES_PACK not enabled)\n";
    return;
#else
    // Certificates pack is linked, but NOT configured on the builder.
    // Requiring a certificates-only fact should fail.
    cose::ValidatorBuilder builder;
    cose::TrustPolicyBuilder policy(builder);

    try {
        cose::RequireX509ChainTrusted(policy);
        (void)policy.Compile();
        throw std::runtime_error("expected policy.Compile() to throw");
    } catch (const cose::cose_error&) {
        // ok
    }
#endif
}

static void test_compile_succeeds_when_required_pack_present() {
#ifndef COSE_HAS_CERTIFICATES_PACK
    std::cout << "SKIP: " << __func__ << " (COSE_HAS_CERTIFICATES_PACK not enabled)\n";
    return;
#else
    cose::ValidatorBuilder builder;
    // Add cert pack to builder using the pack's C API.
    if (cose_validator_builder_with_certificates_pack(builder.native_handle()) != COSE_OK) {
        throw cose::cose_error(COSE_ERR);
    }

    cose::TrustPolicyBuilder policy(builder);
    cose::RequireX509ChainTrusted(policy);

    auto plan = policy.Compile();
    cose::WithCompiledTrustPlan(builder, plan);

    auto validator = builder.Build();
    (void)validator;
#endif
}

static void test_real_v1_policy_can_gate_on_certificate_facts() {
#ifndef COSE_HAS_CERTIFICATES_PACK
    std::cout << "SKIP: " << __func__ << " (COSE_HAS_CERTIFICATES_PACK not enabled)\n";
    return;
#else
    cose::ValidatorBuilder builder;
    if (cose_validator_builder_with_certificates_pack(builder.native_handle()) != COSE_OK) {
        throw cose::cose_error(COSE_ERR);
    }

    cose::TrustPolicyBuilder policy(builder);
    cose::RequireSigningCertificatePresent(policy);
    policy.And();
    cose::RequireNotPqcAlgorithmOrMissing(policy);

    auto plan = policy.Compile();
    (void)plan;
#endif
}

static void test_real_scitt_policy_can_require_cwt_claims_and_mst_receipt_trusted_from_issuer() {
#ifndef COSE_HAS_MST_PACK
    std::cout << "SKIP: " << __func__ << " (COSE_HAS_MST_PACK not enabled)\n";
    return;
#else
    cose::ValidatorBuilder builder;

    if (std::string(COSE_MST_JWKS_PATH).empty()) {
        throw std::runtime_error("COSE_MST_JWKS_PATH not set");
    }

    const auto jwks_json = read_file_bytes(COSE_MST_JWKS_PATH);
    const std::string jwks_str(reinterpret_cast<const char*>(jwks_json.data()), jwks_json.size());

    cose::MstOptions mst;
    mst.allow_network = false;
    mst.offline_jwks_json = jwks_str;

    // Add packs using the C API; avoids needing a multi-pack C++ builder.
    {
        cose_mst_trust_options_t opts;
        opts.allow_network = mst.allow_network;
        opts.offline_jwks_json = mst.offline_jwks_json.c_str();
        opts.jwks_api_version = nullptr;

        if (cose_validator_builder_with_mst_pack_ex(builder.native_handle(), &opts) != COSE_OK) {
            throw cose::cose_error(COSE_ERR);
        }
    }

#ifdef COSE_HAS_CERTIFICATES_PACK
    {
        cose_certificate_trust_options_t cert_opts;
        cert_opts.trust_embedded_chain_as_trusted = true;
        cert_opts.identity_pinning_enabled = false;
        cert_opts.allowed_thumbprints = nullptr;
        cert_opts.pqc_algorithm_oids = nullptr;

        if (cose_validator_builder_with_certificates_pack_ex(builder.native_handle(), &cert_opts) != COSE_OK) {
            throw cose::cose_error(COSE_ERR);
        }
    }
#endif

    cose::TrustPolicyBuilder policy(builder);
    policy.RequireCwtClaimsPresent();
    policy.And();
    cose::RequireMstReceiptTrustedFromIssuerContains(policy, "confidential-ledger.azure.com");

    // This is a policy-shape compilation test (projected helpers exist and compile).
    (void)policy.Compile();
#endif
}

static void test_real_v1_policy_can_validate_with_mst_only_by_bypassing_primary_signature() {
#ifndef COSE_HAS_MST_PACK
    std::cout << "SKIP: " << __func__ << " (COSE_HAS_MST_PACK not enabled)\n";
    return;
#else
    cose::ValidatorBuilder builder;

    const auto jwks_json = read_file_bytes(COSE_MST_JWKS_PATH);
    const std::string jwks_str(reinterpret_cast<const char*>(jwks_json.data()), jwks_json.size());

    {
        cose_mst_trust_options_t opts;
        opts.allow_network = false;
        opts.offline_jwks_json = jwks_str.c_str();
        opts.jwks_api_version = nullptr;

        if (cose_validator_builder_with_mst_pack_ex(builder.native_handle(), &opts) != COSE_OK) {
            throw cose::cose_error(COSE_ERR);
        }
    }

    // Use the MST pack default trust plan (native analogue to Rust's TrustPlanBuilder MST-only test).
    cose::TrustPlanBuilder plan_builder(builder);
    plan_builder.AddAllPackDefaultPlans();
    auto plan = plan_builder.CompileAnd();
    cose::WithCompiledTrustPlan(builder, plan);

    auto validator = builder.Build();

    for (const auto* file : {"2ts-statement.scitt", "1ts-statement.scitt"}) {
        const auto path = join_path2(COSE_TESTDATA_V1_DIR, file);
        const auto cose_bytes = read_file_bytes(path);
        auto result = validator.Validate(cose_bytes);
        if (!result.Ok()) {
            throw std::runtime_error(
                std::string("expected success for ") + file + ", got failure: " + result.FailureMessage()
            );
        }
    }
#endif
}

using test_fn_t = void (*)();

struct test_case_t {
    const char* name;
    test_fn_t fn;
};

static const test_case_t g_tests[] = {
    {"compile_fails_when_required_pack_missing", test_compile_fails_when_required_pack_missing},
    {"compile_succeeds_when_required_pack_present", test_compile_succeeds_when_required_pack_present},
    {"real_v1_policy_can_gate_on_certificate_facts", test_real_v1_policy_can_gate_on_certificate_facts},
    {"real_scitt_policy_can_require_cwt_claims_and_mst_receipt_trusted_from_issuer", test_real_scitt_policy_can_require_cwt_claims_and_mst_receipt_trusted_from_issuer},
    {"real_v1_policy_can_validate_with_mst_only_by_bypassing_primary_signature", test_real_v1_policy_can_validate_with_mst_only_by_bypassing_primary_signature},
};

static void usage(const char* argv0) {
    std::cerr << "Usage:\n";
    std::cerr << "  " << argv0 << " [--list] [--test <name>]\n";
}

static void list_tests() {
    for (const auto& t : g_tests) {
        std::cout << t.name << "\n";
    }
}

static int run_one(const std::string& name) {
    for (const auto& t : g_tests) {
        if (name == t.name) {
            std::cout << "RUN: " << t.name << "\n";
            t.fn();
            std::cout << "PASS: " << t.name << "\n";
            return 0;
        }
    }

    std::cerr << "Unknown test: " << name << "\n";
    return 2;
}

int main(int argc, char** argv) {
#ifndef COSE_HAS_TRUST_PACK
    std::cout << "Skipping: trust pack not available\n";
    return 0;
#else
    try {
        // Minimal subtest runner so CTest can show 1 result per test function.
        // - no args: run all tests
        // - --list: list tests
        // - --test <name>: run one test
        if (argc == 2 && std::string(argv[1]) == "--list") {
            list_tests();
            return 0;
        }

        if (argc == 3 && std::string(argv[1]) == "--test") {
            return run_one(argv[2]);
        }

        if (argc != 1) {
            usage(argv[0]);
            return 2;
        }

        for (const auto& t : g_tests) {
            const int rc = run_one(t.name);
            if (rc != 0) {
                return rc;
            }
        }

        std::cout << "OK\n";
        return 0;
    } catch (const cose::cose_error& e) {
        std::cerr << "cose_error: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "std::exception: " << e.what() << "\n";
        return 1;
    }
#endif
}
