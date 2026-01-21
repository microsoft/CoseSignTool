// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cose/cose.hpp>
#include <iostream>
#include <exception>

int main() {
    try {
        std::cout << "COSE C++ API Smoke Test\n";
        std::cout << "ABI Version: " << cose_ffi_abi_version() << "\n";
        
        // Test 1: Basic builder
        {
            auto builder = cose::ValidatorBuilder();
            auto validator = builder.Build();
            std::cout << "✓ Basic validator built\n";
        }
        
#ifdef COSE_HAS_CERTIFICATES_PACK
        // Test 2: Builder with certificates pack (default options)
        {
            auto builder = cose::ValidatorBuilderWithCertificates();
            builder.WithCertificates();
            auto validator = builder.Build();
            std::cout << "✓ Validator with certificates pack built\n";
        }
        
        // Test 3: Builder with custom certificate options
        {
            cose::CertificateOptions opts;
            opts.trust_embedded_chain_as_trusted = true;
            opts.allowed_thumbprints = {"ABCD1234"};
            
            auto builder = cose::ValidatorBuilderWithCertificates();
            builder.WithCertificates(opts);
            auto validator = builder.Build();
            std::cout << "✓ Validator with custom certificate options built\n";
        }
#endif

#ifdef COSE_HAS_MST_PACK
        // Test 4: Builder with MST pack
        {
            auto builder = cose::ValidatorBuilderWithMst();
            builder.WithMst();
            auto validator = builder.Build();
            std::cout << "✓ Validator with MST pack built\n";
        }
        
        // Test 5: Builder with custom MST options
        {
            cose::MstOptions opts;
            opts.allow_network = false;
            opts.offline_jwks_json = R"({"keys":[]})";
            
            auto builder = cose::ValidatorBuilderWithMst();
            builder.WithMst(opts);
            auto validator = builder.Build();
            std::cout << "✓ Validator with custom MST options built\n";
        }
#endif

#ifdef COSE_HAS_AKV_PACK
        // Test 6: Builder with AKV pack
        {
            auto builder = cose::ValidatorBuilderWithAzureKeyVault();
            builder.WithAzureKeyVault();
            auto validator = builder.Build();
            std::cout << "✓ Validator with AKV pack built\n";
        }
#endif

#ifdef COSE_HAS_TRUST_PACK
    // Test 7: Compile and attach a bundled trust plan
    {
#ifdef COSE_HAS_CERTIFICATES_PACK
        auto builder = cose::ValidatorBuilderWithCertificates();
        builder.WithCertificates();
#else
        auto builder = cose::ValidatorBuilder();
#endif

        auto tp = cose::TrustPlanBuilder(builder);
        auto plan = tp.AddAllPackDefaultPlans().CompileOr();
        cose::WithCompiledTrustPlan(builder, plan);

        auto validator = builder.Build();
        (void)validator;
        std::cout << "✓ Bundled trust plan compiled and attached\n";
    }

    // Test 8: AllowAll/DenyAll plan compilation (no attach)
    {
        auto builder = cose::ValidatorBuilder();
        auto tp = cose::TrustPlanBuilder(builder);

        auto allow_all = tp.CompileAllowAll();
        (void)allow_all;

        auto deny_all = tp.CompileDenyAll();
        (void)deny_all;

        std::cout << "✓ AllowAll/DenyAll plans compiled\n";
    }

    // Test 9: Compile and attach a custom trust policy (message-scope requirements)
    {
        auto builder = cose::ValidatorBuilder();

#ifdef COSE_HAS_CERTIFICATES_PACK
        {
            cose_status_t status = cose_validator_builder_with_certificates_pack(builder.native_handle());
            if (status != COSE_OK) {
                throw cose::cose_error(status);
            }
        }
#endif

#ifdef COSE_HAS_MST_PACK
        {
            cose_status_t status = cose_validator_builder_with_mst_pack(builder.native_handle());
            if (status != COSE_OK) {
                throw cose::cose_error(status);
            }
        }
#endif

#ifdef COSE_HAS_AKV_PACK
        {
            cose_status_t status = cose_validator_builder_with_akv_pack(builder.native_handle());
            if (status != COSE_OK) {
                throw cose::cose_error(status);
            }
        }
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
        std::cout << "✓ Custom trust policy compiled and attached\n";
    }
#endif
        
        std::cout << "\n✅ All C++ smoke tests passed\n";
        return 0;
        
    } catch (const cose::cose_error& e) {
        std::cerr << "COSE error: " << e.what() << "\n";
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Exception: " << e.what() << "\n";
        return 1;
    }
}
