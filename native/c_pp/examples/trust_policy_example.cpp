// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file trust_policy_example.cpp
 * @brief Trust plan authoring — the most important developer workflow.
 *
 * Demonstrates three trust-authoring patterns:
 *   1. Fine-grained TrustPolicyBuilder with And/Or chaining
 *   2. TrustPlanBuilder composing pack default plans
 *   3. Multi-pack validation (certificates + MST)
 *
 * All RAII — no manual free calls, no goto cleanup.
 */

#include <cose/cose.hpp>

#include <cstdint>
#include <ctime>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

/// Read an entire file into a byte vector. Returns false on failure.
static bool read_file_bytes(const std::string& path, std::vector<uint8_t>& out) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        return false;
    }
    f.seekg(0, std::ios::end);
    std::streamoff size = f.tellg();
    if (size < 0) {
        return false;
    }
    f.seekg(0, std::ios::beg);
    out.resize(static_cast<size_t>(size));
    if (!out.empty()) {
        f.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(out.size()));
        if (!f) {
            return false;
        }
    }
    return true;
}

static void usage(const char* argv0) {
    std::cerr
        << "Usage:\n"
        << "  " << argv0 << " <cose_sign1.cose> [detached_payload.bin]\n\n"
        << "Builds a custom trust policy, compiles it, and validates the message.\n";
}

int main(int argc, char** argv) {
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    const std::string cose_path = argv[1];
    const bool has_payload = (argc >= 3);
    const std::string payload_path = has_payload ? argv[2] : std::string();

    std::vector<uint8_t> cose_bytes;
    std::vector<uint8_t> payload_bytes;

    if (!read_file_bytes(cose_path, cose_bytes)) {
        std::cerr << "Failed to read COSE file: " << cose_path << "\n";
        return 2;
    }
    if (has_payload && !read_file_bytes(payload_path, payload_bytes)) {
        std::cerr << "Failed to read payload file: " << payload_path << "\n";
        return 2;
    }

    try {
        // ================================================================
        // Scenario 1: Fine-grained Policy
        // ================================================================
#ifdef COSE_HAS_TRUST_PACK
        std::cout << "=== Scenario 1: Fine-Grained Trust Policy ===" << std::endl;
        {
            cose::ValidatorBuilder builder;
#ifdef COSE_HAS_CERTIFICATES_PACK
            cose::WithCertificates(builder);
#endif
#ifdef COSE_HAS_MST_PACK
            cose::WithMst(builder);
#endif

            // Build a policy with mixed And/Or requirements.
            cose::TrustPolicyBuilder policy(builder);

            // Content type must be set.
            policy.RequireContentTypeEq("application/vnd.example+cbor");

            // CWT claims requirements.
            policy.And();
            policy.RequireCwtClaimsPresent();
            policy.And();
            policy.RequireCwtIssEq("did:x509:example-issuer");
            policy.And();
            policy.RequireCwtSubEq("my-artifact");

            // Time-based CWT constraints.
            int64_t now = static_cast<int64_t>(std::time(nullptr));
            policy.And();
            policy.RequireCwtExpGe(now);
            policy.And();
            policy.RequireCwtNbfLe(now);

#ifdef COSE_HAS_CERTIFICATES_PACK
            // X.509 certificate chain must be present and trusted.
            policy.And();
            cose::RequireX509ChainTrusted(policy);
            cose::RequireSigningCertificatePresent(policy);

            // Pin the leaf certificate subject.
            cose::RequireLeafSubjectEq(policy, "CN=My Signing Cert");

            // Certificate must be valid right now.
            cose::RequireSigningCertificateValidAt(policy, now);
#endif

#ifdef COSE_HAS_MST_PACK
            // MST receipt is an alternative trust signal (OR).
            policy.Or();
            cose::RequireMstReceiptPresent(policy);
            policy.And();
            cose::RequireMstReceiptTrusted(policy);
            cose::RequireMstReceiptIssuerContains(policy, "codetransparency.azure.net");
#endif

            // Compile, attach, build, validate.
            cose::CompiledTrustPlan plan = policy.Compile();
            cose::WithCompiledTrustPlan(builder, plan);

            cose::Validator validator = builder.Build();
            cose::ValidationResult result = has_payload
                ? validator.Validate(cose_bytes, payload_bytes)
                : validator.Validate(cose_bytes);

            std::cout << (result.Ok() ? "Passed" : result.FailureMessage()) << std::endl;
        }
#else
        std::cout << "=== Scenario 1: (SKIPPED — requires COSE_HAS_TRUST_PACK) ===" << std::endl;
#endif

        // ================================================================
        // Scenario 2: Default Plans via TrustPlanBuilder
        // ================================================================
#ifdef COSE_HAS_TRUST_PACK
        std::cout << "\n=== Scenario 2: Default Plans ===" << std::endl;
        {
            cose::ValidatorBuilder builder;
#ifdef COSE_HAS_CERTIFICATES_PACK
            cose::WithCertificates(builder);
#endif
#ifdef COSE_HAS_MST_PACK
            cose::WithMst(builder);
#endif

            // TrustPlanBuilder discovers registered packs and their defaults.
            cose::TrustPlanBuilder plan_builder(builder);

            size_t n = plan_builder.PackCount();
            std::cout << "Discovered " << n << " pack(s):" << std::endl;
            for (size_t i = 0; i < n; ++i) {
                std::cout << "  " << plan_builder.PackName(i)
                          << (plan_builder.PackHasDefaultPlan(i) ? " [default]" : "")
                          << std::endl;
            }

            // Compose all defaults with OR semantics:
            // "pass if ANY pack's default plan is satisfied."
            plan_builder.AddAllPackDefaultPlans();
            cose::CompiledTrustPlan or_plan = plan_builder.CompileOr();

            cose::WithCompiledTrustPlan(builder, or_plan);
            cose::Validator validator = builder.Build();
            cose::ValidationResult result = has_payload
                ? validator.Validate(cose_bytes, payload_bytes)
                : validator.Validate(cose_bytes);

            std::cout << (result.Ok() ? "Passed" : result.FailureMessage()) << std::endl;
        }
#else
        std::cout << "\n=== Scenario 2: (SKIPPED — requires COSE_HAS_TRUST_PACK) ===" << std::endl;
#endif

        // ================================================================
        // Scenario 3: Multi-Pack Validation
        // ================================================================
#if defined(COSE_HAS_CERTIFICATES_PACK) && defined(COSE_HAS_MST_PACK) && defined(COSE_HAS_TRUST_PACK)
        std::cout << "\n=== Scenario 3: Multi-Pack Validation ===" << std::endl;
        {
            // Register both packs with options.
            cose::ValidatorBuilder builder;
            cose::CertificateOptions cert_opts;
            cert_opts.trust_embedded_chain_as_trusted = true;
            cose::WithCertificates(builder, cert_opts);

            cose::MstOptions mst_opts;
            mst_opts.allow_network = false;
            mst_opts.offline_jwks_json = "{\"keys\":[]}";
            cose::WithMst(builder, mst_opts);

            // Combined policy: cert chain trusted AND receipt present.
            cose::TrustPolicyBuilder policy(builder);
            cose::RequireX509ChainTrusted(policy);
            cose::RequireSigningCertificateThumbprintPresent(policy);
            policy.And();
            cose::RequireMstReceiptPresent(policy);
            cose::RequireMstReceiptTrusted(policy);

            cose::CompiledTrustPlan plan = policy.Compile();
            cose::WithCompiledTrustPlan(builder, plan);

            cose::Validator validator = builder.Build();
            cose::ValidationResult result = has_payload
                ? validator.Validate(cose_bytes, payload_bytes)
                : validator.Validate(cose_bytes);

            std::cout << (result.Ok() ? "Passed" : result.FailureMessage()) << std::endl;
        }
#else
        std::cout << "\n=== Scenario 3: (SKIPPED — needs CERTIFICATES + MST + TRUST) ===" << std::endl;
#endif

        return 0;

    } catch (const cose::cose_error& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 3;
    } catch (const std::exception& e) {
        std::cerr << "Unexpected error: " << e.what() << "\n";
        return 3;
    }
}
