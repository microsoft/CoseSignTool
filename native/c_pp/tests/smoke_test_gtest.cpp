// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <gtest/gtest.h>

#include <cose/cose.hpp>

TEST(Smoke, AbiVersionAvailable) {
    EXPECT_GT(cose_sign1_validation_abi_version(), 0u);
}

TEST(Smoke, BasicValidatorBuilds) {
    auto builder = cose::ValidatorBuilder();
    auto validator = builder.Build();
    (void)validator;
}

#ifdef COSE_HAS_CERTIFICATES_PACK
TEST(Smoke, CertificatesPackBuildsDefault) {
    cose::ValidatorBuilder builder;
    cose::WithCertificates(builder);
    auto validator = builder.Build();
    (void)validator;
}

TEST(Smoke, CertificatesPackBuildsCustomOptions) {
    cose::CertificateOptions opts;
    opts.trust_embedded_chain_as_trusted = true;
    opts.allowed_thumbprints = {"ABCD1234"};

    cose::ValidatorBuilder builder;
    cose::WithCertificates(builder, opts);
    auto validator = builder.Build();
    (void)validator;
}
#endif

#ifdef COSE_HAS_MST_PACK
TEST(Smoke, MstPackBuildsDefault) {
    cose::ValidatorBuilder builder;
    cose::WithMst(builder);
    auto validator = builder.Build();
    (void)validator;
}

TEST(Smoke, MstPackBuildsCustomOptions) {
    cose::MstOptions opts;
    opts.allow_network = false;
    opts.offline_jwks_json = R"({"keys":[]})";

    cose::ValidatorBuilder builder;
    cose::WithMst(builder, opts);
    auto validator = builder.Build();
    (void)validator;
}
#endif

#ifdef COSE_HAS_AKV_PACK
TEST(Smoke, AkvPackBuildsDefault) {
    cose::ValidatorBuilder builder;
    cose::WithAzureKeyVault(builder);
    auto validator = builder.Build();
    (void)validator;
}
#endif

#if defined(COSE_HAS_TRUST_PACK) && (defined(COSE_HAS_CERTIFICATES_PACK) || defined(COSE_HAS_MST_PACK) || defined(COSE_HAS_AKV_PACK))
TEST(Smoke, BundledTrustPlanCompilesAndAttaches) {
#ifdef COSE_HAS_CERTIFICATES_PACK
    cose::ValidatorBuilder cert_builder;
    cose::WithCertificates(cert_builder);
    auto builder = std::move(cert_builder);
#else
    auto builder = cose::ValidatorBuilder();
#endif

    auto tp = cose::TrustPlanBuilder(builder);
    auto plan = tp.AddAllPackDefaultPlans().CompileOr();
    cose::WithCompiledTrustPlan(builder, plan);

    auto validator = builder.Build();
    (void)validator;
}
#endif

#ifdef COSE_HAS_TRUST_PACK
    auto builder = cose::ValidatorBuilder();
    auto tp = cose::TrustPlanBuilder(builder);

    auto allow_all = tp.CompileAllowAll();
    (void)allow_all;

    auto deny_all = tp.CompileDenyAll();
    (void)deny_all;
}

TEST(Smoke, CustomTrustPolicyCompilesAndAttaches) {
    auto builder = cose::ValidatorBuilder();

#ifdef COSE_HAS_CERTIFICATES_PACK
    cose::WithCertificates(builder);
#endif
#ifdef COSE_HAS_MST_PACK
    cose::WithMst(builder);
#endif
#ifdef COSE_HAS_AKV_PACK
    cose::WithAzureKeyVault(builder);
#endif

    auto policy = cose::TrustPolicyBuilder(builder);

#ifdef COSE_HAS_CERTIFICATES_PACK
    cose::RequireX509ChainTrusted(policy);
    cose::RequireX509ChainBuilt(policy);
    cose::RequireX509ChainElementCountEq(policy, 1);
    cose::RequireX509ChainStatusFlagsEq(policy, 0);
    cose::RequireLeafChainThumbprintPresent(policy);
    cose::RequireSigningCertificatePresent(policy);
    cose::RequireLeafSubjectEq(policy, "CN=example");
    cose::RequireIssuerSubjectEq(policy, "CN=issuer.example");
    cose::RequireSigningCertificateSubjectIssuerMatchesLeafChainElement(policy);
    cose::RequireLeafIssuerIsNextChainSubjectOptional(policy);
    cose::RequireSigningCertificateThumbprintEq(policy, "ABCD1234");
    cose::RequireSigningCertificateThumbprintPresent(policy);
    cose::RequireSigningCertificateSubjectEq(policy, "CN=example");
    cose::RequireSigningCertificateIssuerEq(policy, "CN=issuer.example");
    cose::RequireSigningCertificateSerialNumberEq(policy, "01");
    cose::RequireSigningCertificateValidAt(policy, 0);
    cose::RequireSigningCertificateExpiredAtOrBefore(policy, 0);
    cose::RequireSigningCertificateNotBeforeLe(policy, 0);
    cose::RequireSigningCertificateNotBeforeGe(policy, 0);
    cose::RequireSigningCertificateNotAfterLe(policy, 0);
    cose::RequireSigningCertificateNotAfterGe(policy, 0);
    cose::RequireChainElementSubjectEq(policy, 0, "CN=example");
    cose::RequireChainElementIssuerEq(policy, 0, "CN=issuer.example");
    cose::RequireChainElementThumbprintPresent(policy, 0);
    cose::RequireChainElementThumbprintEq(policy, 0, "ABCD1234");
    cose::RequireChainElementValidAt(policy, 0, 0);
    cose::RequireChainElementNotBeforeLe(policy, 0, 0);
    cose::RequireChainElementNotBeforeGe(policy, 0, 0);
    cose::RequireChainElementNotAfterLe(policy, 0, 0);
    cose::RequireChainElementNotAfterGe(policy, 0, 0);
    cose::RequireNotPqcAlgorithmOrMissing(policy);
    cose::RequireX509PublicKeyAlgorithmThumbprintEq(policy, "ABCD1234");
    cose::RequireX509PublicKeyAlgorithmOidEq(policy, "1.2.840.113549.1.1.1");
    cose::RequireX509PublicKeyAlgorithmIsNotPqc(policy);
#endif

#ifdef COSE_HAS_MST_PACK
    cose::RequireMstReceiptPresent(policy);
    cose::RequireMstReceiptNotPresent(policy);
    cose::RequireMstReceiptSignatureVerified(policy);
    cose::RequireMstReceiptSignatureNotVerified(policy);
    cose::RequireMstReceiptIssuerContains(policy, "microsoft");
    cose::RequireMstReceiptIssuerEq(policy, "issuer.example");
    cose::RequireMstReceiptKidEq(policy, "kid.example");
    cose::RequireMstReceiptKidContains(policy, "kid");
    cose::RequireMstReceiptTrusted(policy);
    cose::RequireMstReceiptNotTrusted(policy);
    cose::RequireMstReceiptTrustedFromIssuerContains(policy, "microsoft");
    cose::RequireMstReceiptStatementSha256Eq(
        policy,
        "0000000000000000000000000000000000000000000000000000000000000000");
    cose::RequireMstReceiptStatementCoverageEq(policy, "coverage.example");
    cose::RequireMstReceiptStatementCoverageContains(policy, "example");
#endif

#ifdef COSE_HAS_AKV_PACK
    cose::RequireAzureKeyVaultKid(policy);
    cose::RequireAzureKeyVaultKidAllowed(policy);
    cose::RequireNotAzureKeyVaultKid(policy);
    cose::RequireAzureKeyVaultKidNotAllowed(policy);
#endif

    auto plan = policy
                    .RequireDetachedPayloadAbsent()
                    .RequireCwtClaimsPresent()
                    .RequireCwtIssEq("issuer.example")
                    .RequireCwtClaimLabelPresent(6)
                    .RequireCwtClaimLabelI64Ge(6, 123)
                    .RequireCwtClaimLabelBoolEq(6, true)
                    .RequireCwtClaimTextStrEq("nonce", "abc")
                    .RequireCwtClaimTextStrStartsWith("nonce", "a")
                    .RequireCwtClaimTextStrContains("nonce", "b")
                    .RequireCwtClaimLabelStrStartsWith(1000, "a")
                    .RequireCwtClaimLabelStrContains(1000, "b")
                    .RequireCwtClaimLabelStrEq(1000, "exact.example")
                    .RequireCwtClaimTextI64Le("nonce", 0)
                    .RequireCwtClaimTextI64Eq("nonce", 0)
                    .RequireCwtClaimTextBoolEq("nonce", true)
                    .RequireCwtExpGe(0)
                    .RequireCwtIatLe(0)
                    .RequireCounterSignatureEnvelopeSigStructureIntactOrMissing()
                    .Compile();

    cose::WithCompiledTrustPlan(builder, plan);

    auto validator = builder.Build();
    (void)validator;
}
#endif
