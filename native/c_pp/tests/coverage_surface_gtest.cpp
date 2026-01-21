// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <gtest/gtest.h>

#include <cose/cose.hpp>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

TEST(CoverageSurface, TrustAndCoreBuilders) {
    // Cover CompiledTrustPlan null-guard.
    EXPECT_THROW((void)cose::CompiledTrustPlan(nullptr), cose::cose_error);

    // Cover ValidatorBuilder move ops and the "consumed" error path.
    cose::ValidatorBuilder b1;
    cose::ValidatorBuilder b2(std::move(b1));
    cose::ValidatorBuilder b3;
    b3 = std::move(b2);

    EXPECT_THROW((void)b1.Build(), cose::cose_error);

    // Exercise TrustPolicyBuilder surface.
    cose::TrustPolicyBuilder p(b3);
    p.And()
        .RequireContentTypeNonEmpty()
        .RequireContentTypeEq("application/cose")
        .Or()
        .RequireDetachedPayloadPresent()
        .RequireDetachedPayloadAbsent()
        .RequireCounterSignatureEnvelopeSigStructureIntactOrMissing()
        .RequireCwtClaimsPresent()
        .RequireCwtClaimsAbsent()
        .RequireCwtIssEq("issuer")
        .RequireCwtSubEq("subject")
        .RequireCwtAudEq("aud")
        .RequireCwtClaimLabelPresent(1)
        .RequireCwtClaimTextPresent("k")
        .RequireCwtClaimLabelI64Eq(2, 42)
        .RequireCwtClaimLabelBoolEq(3, true)
        .RequireCwtClaimLabelI64Ge(4, 0)
        .RequireCwtClaimLabelI64Le(5, 100)
        .RequireCwtClaimTextStrEq("k2", "v2")
        .RequireCwtClaimLabelStrEq(6, "v")
        .RequireCwtClaimLabelStrStartsWith(7, "pre")
        .RequireCwtClaimTextStrStartsWith("k3", "pre")
        .RequireCwtClaimLabelStrContains(8, "needle")
        .RequireCwtClaimTextStrContains("k4", "needle")
        .RequireCwtClaimTextBoolEq("k5", false)
        .RequireCwtClaimTextI64Eq("k6", -1)
        .RequireCwtClaimTextI64Ge("k7", 0)
        .RequireCwtClaimTextI64Le("k8", 123)
        .RequireCwtExpGe(0)
        .RequireCwtExpLe(4102444800)  // 2100-01-01
        .RequireCwtNbfGe(0)
        .RequireCwtNbfLe(4102444800)
        .RequireCwtIatGe(0)
        .RequireCwtIatLe(4102444800);

    // Exercise TrustPlanBuilder surface.
    cose::TrustPlanBuilder plan_builder(b3);
    EXPECT_NO_THROW((void)plan_builder.AddAllPackDefaultPlans());

    const size_t pack_count = plan_builder.PackCount();
    // Cover PackName failure path (out-of-range index).
    EXPECT_THROW((void)plan_builder.PackName(pack_count), cose::cose_error);

    for (size_t i = 0; i < pack_count; ++i) {
        const auto name = plan_builder.PackName(i);
        (void)plan_builder.PackHasDefaultPlan(i);
        if (plan_builder.PackHasDefaultPlan(i)) {
            EXPECT_NO_THROW((void)plan_builder.AddPackDefaultPlanByName(name));
        }
    }

    EXPECT_NO_THROW((void)plan_builder.ClearSelectedPlans());

    // Cover compile helpers that should not depend on selected plans.
    auto allow_all = plan_builder.CompileAllowAll();
    auto deny_all = plan_builder.CompileDenyAll();

    // Cover CompiledTrustPlan move operations.
    cose::CompiledTrustPlan moved_plan(std::move(deny_all));
    deny_all = std::move(moved_plan);

    // Cover CompiledTrustPlan move-assignment branch where the destination already owns a plan.
    auto allow_all2 = plan_builder.CompileAllowAll();
    auto deny_all2 = plan_builder.CompileDenyAll();
    allow_all2 = std::move(deny_all2);

    // Cover TrustPlanBuilder move-assignment branch where the destination already owns a builder.
    cose::TrustPlanBuilder tb1(b3);
    cose::TrustPlanBuilder tb2(b3);
    tb1 = std::move(tb2);
    EXPECT_NO_THROW((void)tb1.PackCount());
    EXPECT_THROW((void)tb2.PackCount(), cose::cose_error);

    cose::ValidatorBuilder b4;
    EXPECT_NO_THROW((void)cose::WithCompiledTrustPlan(b4, allow_all));

    // Cover WithCompiledTrustPlan error path by using a moved-from builder handle.
    cose::ValidatorBuilder moved_from;
    cose::ValidatorBuilder moved_to(std::move(moved_from));
    (void)moved_to;
    EXPECT_THROW((void)cose::WithCompiledTrustPlan(moved_from, allow_all), cose::cose_error);

    // Cover CheckBuilder() failure on TrustPolicyBuilder.
    cose::TrustPolicyBuilder p2(std::move(p));
    EXPECT_THROW((void)p.And(), cose::cose_error);

    // Use p2 so it stays alive and is destroyed cleanly.
    EXPECT_NO_THROW((void)p2.Compile());
}

TEST(CoverageSurface, ThrowsWhenValidatorBuilderConsumed) {
    // Ensure ThrowIfNotOkOrNull is covered for constructors that wrap a C "new" API.
    cose::ValidatorBuilder b;
    auto validator = b.Build();
    (void)validator;

    EXPECT_THROW((void)cose::TrustPlanBuilder(b), cose::cose_error);
    EXPECT_THROW((void)cose::TrustPolicyBuilder(b), cose::cose_error);
}

#ifdef COSE_HAS_CERTIFICATES_PACK
TEST(CoverageSurface, CertificatesPackAndPolicyHelpers) {
    cose::ValidatorBuilderWithCertificates b;

    cose::CertificateOptions opts;
    opts.trust_embedded_chain_as_trusted = true;
    opts.identity_pinning_enabled = true;
    opts.allowed_thumbprints = {"aa", "bb"};
    opts.pqc_algorithm_oids = {"1.2.3.4"};

    EXPECT_NO_THROW((void)b.WithCertificates());
    EXPECT_NO_THROW((void)b.WithCertificates(opts));

    cose::TrustPolicyBuilder policy(b);

    // Exercise all certificates trust-policy helpers.
    cose::RequireX509ChainTrusted(policy);
    cose::RequireX509ChainNotTrusted(policy);
    cose::RequireX509ChainBuilt(policy);
    cose::RequireX509ChainNotBuilt(policy);
    cose::RequireX509ChainElementCountEq(policy, 2);
    cose::RequireX509ChainStatusFlagsEq(policy, 0);
    cose::RequireLeafChainThumbprintPresent(policy);
    cose::RequireSigningCertificatePresent(policy);
    cose::RequireLeafSubjectEq(policy, "CN=leaf");
    cose::RequireIssuerSubjectEq(policy, "CN=issuer");
    cose::RequireSigningCertificateSubjectIssuerMatchesLeafChainElement(policy);
    cose::RequireLeafIssuerIsNextChainSubjectOptional(policy);
    cose::RequireSigningCertificateThumbprintEq(policy, "00");
    cose::RequireSigningCertificateThumbprintPresent(policy);
    cose::RequireSigningCertificateSubjectEq(policy, "CN=leaf");
    cose::RequireSigningCertificateIssuerEq(policy, "CN=issuer");
    cose::RequireSigningCertificateSerialNumberEq(policy, "01");
    cose::RequireSigningCertificateExpiredAtOrBefore(policy, 0);
    cose::RequireSigningCertificateValidAt(policy, 0);
    cose::RequireSigningCertificateNotBeforeLe(policy, 0);
    cose::RequireSigningCertificateNotBeforeGe(policy, 0);
    cose::RequireSigningCertificateNotAfterLe(policy, 0);
    cose::RequireSigningCertificateNotAfterGe(policy, 0);
    cose::RequireChainElementSubjectEq(policy, 0, "CN=leaf");
    cose::RequireChainElementIssuerEq(policy, 0, "CN=issuer");
    cose::RequireChainElementThumbprintEq(policy, 0, "00");
    cose::RequireChainElementThumbprintPresent(policy, 0);
    cose::RequireChainElementValidAt(policy, 0, 0);
    cose::RequireChainElementNotBeforeLe(policy, 0, 0);
    cose::RequireChainElementNotBeforeGe(policy, 0, 0);
    cose::RequireChainElementNotAfterLe(policy, 0, 0);
    cose::RequireChainElementNotAfterGe(policy, 0, 0);
    cose::RequireNotPqcAlgorithmOrMissing(policy);
    cose::RequireX509PublicKeyAlgorithmThumbprintEq(policy, "00");
    cose::RequireX509PublicKeyAlgorithmOidEq(policy, "1.2.3.4");
    cose::RequireX509PublicKeyAlgorithmIsPqc(policy);
    cose::RequireX509PublicKeyAlgorithmIsNotPqc(policy);

    // Cover the error branch in helper functions by calling them on a moved-from builder.
    cose::TrustPolicyBuilder policy2(std::move(policy));
    EXPECT_THROW((void)cose::RequireX509ChainTrusted(policy), cose::cose_error);

    // Keep policy2 alive for cleanup.
    EXPECT_NO_THROW((void)policy2.Compile());
}
#endif

#ifdef COSE_HAS_MST_PACK
TEST(CoverageSurface, MstPackAndPolicyHelpers) {
    cose::ValidatorBuilderWithMst b;

    cose::MstOptions opts;
    opts.allow_network = false;
    opts.offline_jwks_json = "{\"keys\":[]}";
    opts.jwks_api_version = "2023-01-01";

    EXPECT_NO_THROW((void)b.WithMst());
    EXPECT_NO_THROW((void)b.WithMst(opts));

    cose::TrustPolicyBuilder policy(b);

    cose::RequireMstReceiptPresent(policy);
    cose::RequireMstReceiptNotPresent(policy);
    cose::RequireMstReceiptSignatureVerified(policy);
    cose::RequireMstReceiptSignatureNotVerified(policy);
    cose::RequireMstReceiptIssuerContains(policy, "issuer");
    cose::RequireMstReceiptIssuerEq(policy, "issuer");
    cose::RequireMstReceiptKidEq(policy, "kid");
    cose::RequireMstReceiptKidContains(policy, "kid");
    cose::RequireMstReceiptTrusted(policy);
    cose::RequireMstReceiptNotTrusted(policy);
    cose::RequireMstReceiptTrustedFromIssuerContains(policy, "issuer");
    cose::RequireMstReceiptStatementSha256Eq(policy, "00");
    cose::RequireMstReceiptStatementCoverageEq(policy, "coverage");
    cose::RequireMstReceiptStatementCoverageContains(policy, "cov");

    cose::TrustPolicyBuilder policy2(std::move(policy));
    EXPECT_THROW((void)cose::RequireMstReceiptPresent(policy), cose::cose_error);
    EXPECT_NO_THROW((void)policy2.Compile());
}
#endif

#ifdef COSE_HAS_AKV_PACK
TEST(CoverageSurface, AkvPackAndPolicyHelpers) {
    cose::ValidatorBuilderWithAzureKeyVault b;

    cose::AzureKeyVaultOptions opts;
    opts.require_azure_key_vault_kid = true;
    opts.allowed_kid_patterns = {"*.vault.azure.net/keys/*"};

    EXPECT_NO_THROW((void)b.WithAzureKeyVault());
    EXPECT_NO_THROW((void)b.WithAzureKeyVault(opts));

    cose::TrustPolicyBuilder policy(b);

    cose::RequireAzureKeyVaultKid(policy);
    cose::RequireNotAzureKeyVaultKid(policy);
    cose::RequireAzureKeyVaultKidAllowed(policy);
    cose::RequireAzureKeyVaultKidNotAllowed(policy);

    cose::TrustPolicyBuilder policy2(std::move(policy));
    EXPECT_THROW((void)cose::RequireAzureKeyVaultKid(policy), cose::cose_error);
    EXPECT_NO_THROW((void)policy2.Compile());
}
#endif
