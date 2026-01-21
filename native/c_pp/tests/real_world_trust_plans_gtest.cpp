// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <gtest/gtest.h>

#include <cose/trust.hpp>

#ifdef COSE_HAS_CERTIFICATES_PACK
#include <cose/certificates.hpp>
#endif

#ifdef COSE_HAS_MST_PACK
#include <cose/mst.hpp>
#endif

#include <cstdint>
#include <fstream>
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

TEST(RealWorldTrustPlans, CompileFailsWhenRequiredPackMissing) {
#ifndef COSE_HAS_TRUST_PACK
    GTEST_SKIP() << "trust pack not available";
#else
#ifndef COSE_HAS_CERTIFICATES_PACK
    GTEST_SKIP() << "COSE_HAS_CERTIFICATES_PACK not enabled";
#else
    // Certificates pack is linked, but NOT configured on the builder.
    // Requiring a certificates-only fact should fail.
    cose::ValidatorBuilder builder;
    cose::TrustPolicyBuilder policy(builder);

    try {
        cose::RequireX509ChainTrusted(policy);
        (void)policy.Compile();
        FAIL() << "expected policy.Compile() to throw";
    } catch (const cose::cose_error&) {
        SUCCEED();
    }
#endif
#endif
}

TEST(RealWorldTrustPlans, CompileSucceedsWhenRequiredPackPresent) {
#ifndef COSE_HAS_TRUST_PACK
    GTEST_SKIP() << "trust pack not available";
#else
#ifndef COSE_HAS_CERTIFICATES_PACK
    GTEST_SKIP() << "COSE_HAS_CERTIFICATES_PACK not enabled";
#else
    cose::ValidatorBuilder builder;

    ASSERT_EQ(cose_validator_builder_with_certificates_pack(builder.native_handle()), COSE_OK);

    cose::TrustPolicyBuilder policy(builder);
    cose::RequireX509ChainTrusted(policy);

    auto plan = policy.Compile();
    cose::WithCompiledTrustPlan(builder, plan);

    auto validator = builder.Build();
    (void)validator;
#endif
#endif
}

TEST(RealWorldTrustPlans, RealV1PolicyCanGateOnCertificateFacts) {
#ifndef COSE_HAS_TRUST_PACK
    GTEST_SKIP() << "trust pack not available";
#else
#ifndef COSE_HAS_CERTIFICATES_PACK
    GTEST_SKIP() << "COSE_HAS_CERTIFICATES_PACK not enabled";
#else
    cose::ValidatorBuilder builder;
    ASSERT_EQ(cose_validator_builder_with_certificates_pack(builder.native_handle()), COSE_OK);

    cose::TrustPolicyBuilder policy(builder);
    cose::RequireSigningCertificatePresent(policy);
    policy.And();
    cose::RequireNotPqcAlgorithmOrMissing(policy);

    auto plan = policy.Compile();
    (void)plan;
#endif
#endif
}

TEST(RealWorldTrustPlans, RealScittPolicyCanRequireCwtClaimsAndMstReceiptTrustedFromIssuer) {
#ifndef COSE_HAS_TRUST_PACK
    GTEST_SKIP() << "trust pack not available";
#else
#ifndef COSE_HAS_MST_PACK
    GTEST_SKIP() << "COSE_HAS_MST_PACK not enabled";
#else
    cose::ValidatorBuilder builder;

    if (std::string(COSE_MST_JWKS_PATH).empty()) {
        FAIL() << "COSE_MST_JWKS_PATH not set";
    }

    const auto jwks_json = read_file_bytes(COSE_MST_JWKS_PATH);
    const std::string jwks_str(reinterpret_cast<const char*>(jwks_json.data()), jwks_json.size());

    {
        cose_mst_trust_options_t opts;
        opts.allow_network = false;
        opts.offline_jwks_json = jwks_str.c_str();
        opts.jwks_api_version = nullptr;

        ASSERT_EQ(cose_validator_builder_with_mst_pack_ex(builder.native_handle(), &opts), COSE_OK);
    }

#ifdef COSE_HAS_CERTIFICATES_PACK
    {
        cose_certificate_trust_options_t cert_opts;
        cert_opts.trust_embedded_chain_as_trusted = true;
        cert_opts.identity_pinning_enabled = false;
        cert_opts.allowed_thumbprints = nullptr;
        cert_opts.pqc_algorithm_oids = nullptr;

        ASSERT_EQ(cose_validator_builder_with_certificates_pack_ex(builder.native_handle(), &cert_opts), COSE_OK);
    }
#endif

    cose::TrustPolicyBuilder policy(builder);
    policy.RequireCwtClaimsPresent();
    policy.And();
    cose::RequireMstReceiptTrustedFromIssuerContains(policy, "confidential-ledger.azure.com");

    (void)policy.Compile();
#endif
#endif
}

TEST(RealWorldTrustPlans, RealV1PolicyCanValidateWithMstOnlyBypassingPrimarySignature) {
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

    cose::ValidatorBuilder builder;

    const auto jwks_json = read_file_bytes(COSE_MST_JWKS_PATH);
    const std::string jwks_str(reinterpret_cast<const char*>(jwks_json.data()), jwks_json.size());

    {
        cose_mst_trust_options_t opts;
        opts.allow_network = false;
        opts.offline_jwks_json = jwks_str.c_str();
        opts.jwks_api_version = nullptr;

        ASSERT_EQ(cose_validator_builder_with_mst_pack_ex(builder.native_handle(), &opts), COSE_OK);
    }

    // Use the MST pack default trust plan.
    cose::TrustPlanBuilder plan_builder(builder);
    plan_builder.AddAllPackDefaultPlans();
    auto plan = plan_builder.CompileAnd();
    cose::WithCompiledTrustPlan(builder, plan);

    auto validator = builder.Build();

    for (const auto* file : {"2ts-statement.scitt", "1ts-statement.scitt"}) {
        const auto path = join_path2(COSE_TESTDATA_V1_DIR, file);
        const auto cose_bytes = read_file_bytes(path);
        auto result = validator.Validate(cose_bytes);
        ASSERT_TRUE(result.Ok()) << "expected success for " << file << ", got failure: "
                                 << result.FailureMessage();
    }
#endif
#endif
}
