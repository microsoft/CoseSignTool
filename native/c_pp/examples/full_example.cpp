// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file full_example.cpp
 * @brief Comprehensive C++ example demonstrating COSE Sign1 validation with RAII
 *
 * This example shows the full range of the C++ API, including:
 * - Basic validation (always available)
 * - Trust policy authoring with certificates and MST packs
 * - Multi-pack composition with AND/OR operators
 * - Trust plan builder for composing pack default plans
 * - Message parsing and header inspection
 * - CWT claims building and serialization
 *
 * Compare with the C examples to see the RAII advantage: no goto cleanup,
 * no manual free calls, and exception-based error handling.
 */

#include <cose/cose.hpp>

#include <cstdint>
#include <ctime>
#include <iostream>
#include <string>
#include <vector>

int main() {
    try {
        // Dummy COSE Sign1 bytes for demonstration purposes.
        // In production, these would come from a file or network.
        std::vector<uint8_t> cose_bytes = {
            0xD2, 0x84, 0x43, 0xA1, 0x01, 0x26, 0xA0, 0x44,
            0x74, 0x65, 0x73, 0x74, 0x40
        };

        // ====================================================================
        // Part 1: Basic Validation (always available)
        // ====================================================================
        std::cout << "=== Part 1: Basic Validation ===" << std::endl;
        {
            // ValidatorBuilder → Build → Validate.
            // All three RAII objects are destroyed automatically at scope exit.
            cose::ValidatorBuilder builder;
            cose::Validator validator = builder.Build();
            cose::ValidationResult result = validator.Validate(cose_bytes);

            if (result.Ok()) {
                std::cout << "Validation succeeded" << std::endl;
            } else {
                std::cout << "Validation failed: " << result.FailureMessage() << std::endl;
            }
        }
        // No cleanup code needed — RAII destructors freed builder, validator, and result.

        // ====================================================================
        // Part 2: Validation with Trust Policy + Certificates Pack
        // ====================================================================
#if defined(COSE_HAS_CERTIFICATES_PACK) && defined(COSE_HAS_TRUST_PACK)
        std::cout << "\n=== Part 2: Trust Policy + Certificates ===" << std::endl;
        {
            // Create a plain ValidatorBuilder and register the certificates pack
            // using the composable free function (no subclass required).
            cose::ValidatorBuilder builder;
            cose::CertificateOptions cert_opts;
            cert_opts.trust_embedded_chain_as_trusted = true;
            cose::WithCertificates(builder, cert_opts);

            // Build a trust policy with fluent chaining.
            cose::TrustPolicyBuilder policy(builder);
            policy
                .RequireContentTypeNonEmpty()
                .And();
            cose::RequireX509ChainTrusted(policy);
            cose::RequireSigningCertificatePresent(policy);
            cose::RequireSigningCertificateThumbprintPresent(policy);

            // Compile to an optimized plan and attach to the builder.
            cose::CompiledTrustPlan plan = policy.Compile();
            cose::WithCompiledTrustPlan(builder, plan);

            // Build and validate.
            cose::Validator validator = builder.Build();
            cose::ValidationResult result = validator.Validate(cose_bytes);

            std::cout << (result.Ok() ? "Passed" : result.FailureMessage()) << std::endl;
        }
#else
        std::cout << "\n=== Part 2: Trust Policy + Certificates (SKIPPED) ===" << std::endl;
        std::cout << "Requires: COSE_HAS_CERTIFICATES_PACK, COSE_HAS_TRUST_PACK" << std::endl;
#endif

        // ====================================================================
        // Part 3: Multi-Pack Composition (Certificates + MST)
        // ====================================================================
#if defined(COSE_HAS_CERTIFICATES_PACK) && defined(COSE_HAS_MST_PACK) && defined(COSE_HAS_TRUST_PACK)
        std::cout << "\n=== Part 3: Multi-Pack Composition ===" << std::endl;
        {
            // Register both packs on the same builder using free functions.
            cose::ValidatorBuilder builder;
            cose::WithCertificates(builder);
            cose::MstOptions mst_opts;
            mst_opts.allow_network = false;
            mst_opts.offline_jwks_json = "{\"keys\":[]}";
            cose::WithMst(builder, mst_opts);

            // Build a combined policy mixing certificate AND MST requirements.
            cose::TrustPolicyBuilder policy(builder);
            cose::RequireX509ChainTrusted(policy);
            policy.And();
            cose::RequireSigningCertificatePresent(policy);
            policy.Or();
            cose::RequireMstReceiptPresent(policy);
            policy.And();
            cose::RequireMstReceiptTrusted(policy);

            cose::CompiledTrustPlan plan = policy.Compile();
            cose::WithCompiledTrustPlan(builder, plan);

            cose::Validator validator = builder.Build();
            cose::ValidationResult result = validator.Validate(cose_bytes);

            std::cout << (result.Ok() ? "Passed" : result.FailureMessage()) << std::endl;
        }
#else
        std::cout << "\n=== Part 3: Multi-Pack Composition (SKIPPED) ===" << std::endl;
        std::cout << "Requires: COSE_HAS_CERTIFICATES_PACK, COSE_HAS_MST_PACK, COSE_HAS_TRUST_PACK" << std::endl;
#endif

        // ====================================================================
        // Part 4: Trust Plan Builder — inspect packs and compose default plans
        // ====================================================================
#ifdef COSE_HAS_TRUST_PACK
        std::cout << "\n=== Part 4: Trust Plan Builder ===" << std::endl;
        {
            cose::ValidatorBuilder builder;

            // Register packs so the plan builder can discover them.
#ifdef COSE_HAS_CERTIFICATES_PACK
            cose::WithCertificates(builder);
#endif
#ifdef COSE_HAS_MST_PACK
            cose::WithMst(builder);
#endif

            cose::TrustPlanBuilder plan_builder(builder);

            // Enumerate registered packs.
            size_t pack_count = plan_builder.PackCount();
            std::cout << "Registered packs: " << pack_count << std::endl;
            for (size_t i = 0; i < pack_count; ++i) {
                std::cout << "  [" << i << "] " << plan_builder.PackName(i)
                          << " (has default plan: "
                          << (plan_builder.PackHasDefaultPlan(i) ? "yes" : "no")
                          << ")" << std::endl;
            }

            // Compose all pack default plans with OR semantics.
            plan_builder.AddAllPackDefaultPlans();
            cose::CompiledTrustPlan or_plan = plan_builder.CompileOr();
            std::cout << "Compiled OR plan from all defaults" << std::endl;

            // Re-compose with AND semantics (clear previous selections first).
            plan_builder.ClearSelectedPlans();
            plan_builder.AddAllPackDefaultPlans();
            cose::CompiledTrustPlan and_plan = plan_builder.CompileAnd();
            std::cout << "Compiled AND plan from all defaults" << std::endl;

            // Attach the OR plan and validate.
            cose::WithCompiledTrustPlan(builder, or_plan);
            cose::Validator validator = builder.Build();
            cose::ValidationResult result = validator.Validate(cose_bytes);
            std::cout << (result.Ok() ? "Passed" : result.FailureMessage()) << std::endl;
        }
#else
        std::cout << "\n=== Part 4: Trust Plan Builder (SKIPPED) ===" << std::endl;
        std::cout << "Requires: COSE_HAS_TRUST_PACK" << std::endl;
#endif

        // ====================================================================
        // Part 5: Message Parsing (COSE_Sign1 structure inspection)
        // ====================================================================
#ifdef COSE_HAS_PRIMITIVES
        std::cout << "\n=== Part 5: Message Parsing ===" << std::endl;
        {
            // Parse raw bytes into a CoseSign1Message.
            cose::CoseSign1Message msg = cose::CoseSign1Message::Parse(cose_bytes);

            // Algorithm is optional — may not be present in all messages.
            std::optional<int64_t> alg = msg.Algorithm();
            if (alg.has_value()) {
                std::cout << "Algorithm: " << *alg << std::endl;
            }

            std::cout << "Detached: " << (msg.IsDetached() ? "yes" : "no") << std::endl;

            // Inspect protected headers.
            cose::CoseHeaderMap protected_hdrs = msg.ProtectedHeaders();
            std::cout << "Protected header count: " << protected_hdrs.Len() << std::endl;

            std::optional<std::string> ct = protected_hdrs.GetText(3); // label 3 = content type
            if (ct.has_value()) {
                std::cout << "Content-Type: " << *ct << std::endl;
            }

            // Payload and signature.
            std::optional<std::vector<uint8_t>> payload = msg.Payload();
            if (payload.has_value()) {
                std::cout << "Payload: " << payload->size() << " bytes" << std::endl;
            } else {
                std::cout << "Payload: <detached>" << std::endl;
            }

            std::vector<uint8_t> sig = msg.Signature();
            std::cout << "Signature: " << sig.size() << " bytes" << std::endl;

            // Unprotected headers are also available.
            cose::CoseHeaderMap unprotected_hdrs = msg.UnprotectedHeaders();
            std::cout << "Unprotected header count: " << unprotected_hdrs.Len() << std::endl;
        }
#else
        std::cout << "\n=== Part 5: Message Parsing (SKIPPED) ===" << std::endl;
        std::cout << "Requires: COSE_HAS_PRIMITIVES" << std::endl;
#endif

        // ====================================================================
        // Part 6: CWT Claims — build claims and serialize to CBOR
        // ====================================================================
#ifdef COSE_HAS_CWT_HEADERS
        std::cout << "\n=== Part 6: CWT Claims ===" << std::endl;
        {
            int64_t now = static_cast<int64_t>(std::time(nullptr));

            // Fluent builder for CWT claims (RFC 8392).
            cose::CwtClaims claims = cose::CwtClaims::New();
            claims
                .SetIssuer("did:x509:example-issuer")
                .SetSubject("my-artifact")
                .SetAudience("https://contoso.com")
                .SetIssuedAt(now)
                .SetNotBefore(now)
                .SetExpiration(now + 3600);

            // Read back
            std::optional<std::string> iss = claims.GetIssuer();
            if (iss.has_value()) {
                std::cout << "Issuer: " << *iss << std::endl;
            }
            std::optional<std::string> sub = claims.GetSubject();
            if (sub.has_value()) {
                std::cout << "Subject: " << *sub << std::endl;
            }

            // Serialize to CBOR bytes (for embedding in COSE protected headers).
            std::vector<uint8_t> cbor = claims.ToCbor();
            std::cout << "Serialized CWT claims: " << cbor.size() << " CBOR bytes" << std::endl;

            // Round-trip: deserialize and verify.
            cose::CwtClaims parsed = cose::CwtClaims::FromCbor(cbor);
            std::optional<std::string> rt_iss = parsed.GetIssuer();
            std::cout << "Round-trip issuer: " << rt_iss.value_or("<missing>") << std::endl;
        }
#else
        std::cout << "\n=== Part 6: CWT Claims (SKIPPED) ===" << std::endl;
        std::cout << "Requires: COSE_HAS_CWT_HEADERS" << std::endl;
#endif

        // ====================================================================
        // Summary: C++ RAII advantages over the C API
        // ====================================================================
        std::cout << "\n=== Summary ===" << std::endl;
        std::cout << "No manual cleanup — destructors free every handle" << std::endl;
        std::cout << "No goto cleanup  — exceptions unwind the stack safely" << std::endl;
        std::cout << "Type safety      — std::string, std::vector, std::optional" << std::endl;
        std::cout << "Move semantics   — zero-copy ownership transfer" << std::endl;

        return 0;

    } catch (const cose::cose_error& e) {
        std::cerr << "COSE error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
}
