// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file full_example.cpp
 * @brief Comprehensive C++ example demonstrating real COSE Sign1 signing with RAII
 * 
 * This example shows the complete workflow from certificate generation through signing
 * to validation, using real cryptographic operations. It demonstrates:
 * - RAII resource management (no manual cleanup)
 * - Real ECDSA and ML-DSA-65 signatures (no dummy callbacks)
 * - Certificate chain creation
 * - Post-quantum cryptography (when available)
 * - Exception-based error handling
 */

#include <cose/cose.hpp>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

int main() {
    try {
        // Example payload to sign
        const std::string payload_text = "Hello, COSE Sign1 from C++!";
        std::vector<uint8_t> payload(payload_text.begin(), payload_text.end());

        std::vector<uint8_t> signed_bytes;

        // ========================================================================
        // Part 1: Real Signing with Self-Signed Certificate
        // ========================================================================
#if defined(COSE_HAS_CERTIFICATES_LOCAL) && defined(COSE_HAS_CRYPTO_OPENSSL) && defined(COSE_HAS_FACTORIES)
        std::cout << "=== Part 1: Self-Signed Certificate Signing ===" << std::endl;
        
        // Generate ephemeral self-signed certificate with ECDSA P-256
        auto cert = cose::EphemeralCertificateFactory::New().CreateSelfSigned();
        std::cout << "✓ Generated self-signed certificate" << std::endl;
        
        // Create signer from the private key
        auto signer = cose::CryptoProvider::New().SignerFromDer(cert.key_der);
        std::cout << "✓ Created signer (algorithm: " << signer.Algorithm() << ")" << std::endl;
        
        // Create factory and sign - DIRECT crypto flow (no callback!)
        auto factory = cose::SignatureFactory::FromCryptoSigner(signer);
        signed_bytes = factory.SignDirectBytes(
            payload.data(), 
            static_cast<uint32_t>(payload.size()), 
            "application/example"
        );
        std::cout << "✓ Signed with real ECDSA signature (" << signed_bytes.size() << " bytes)" << std::endl;
#else
        std::cout << "=== Part 1: Self-Signed Certificate Signing (SKIPPED - feature not available) ===" << std::endl;
        std::cout << "Requires: COSE_HAS_CERTIFICATES_LOCAL, COSE_HAS_CRYPTO_OPENSSL, COSE_HAS_FACTORIES" << std::endl;
#endif

        // ========================================================================
        // Part 2: Certificate Chain Signing
        // ========================================================================
#if defined(COSE_HAS_CERTIFICATES_LOCAL) && defined(COSE_HAS_CRYPTO_OPENSSL) && defined(COSE_HAS_FACTORIES)
        std::cout << "\n=== Part 2: Certificate Chain Signing ===" << std::endl;
        
        // Create certificate chain factory
        auto chain_factory = cose::CertificateChainFactory::New();
        
        // Generate a certificate chain (ECDSA with intermediate CA)
        auto chain = chain_factory.CreateChain(COSE_KEY_ALG_ECDSA, true);
        std::cout << "✓ Generated certificate chain" << std::endl;
        std::cout << "  Chain length: " << chain.size() << " certificates" << std::endl;
        
        if (chain.size() > 0) {
            // Use the leaf certificate (first in chain) for signing
            std::cout << "  Leaf cert size: " << chain[0].cert_der.size() << " bytes" << std::endl;
            std::cout << "  Leaf key size: " << chain[0].key_der.size() << " bytes" << std::endl;
            
            if (chain.size() > 1) {
                std::cout << "  Intermediate cert size: " << chain[1].cert_der.size() << " bytes" << std::endl;
            }
            if (chain.size() > 2) {
                std::cout << "  Root cert size: " << chain[2].cert_der.size() << " bytes" << std::endl;
            }
            
            // Create signer from leaf certificate's private key
            auto chain_crypto = cose::CryptoProvider::New();
            auto chain_signer = chain_crypto.SignerFromDer(chain[0].key_der);
            
            // Create factory DIRECTLY from signer (no callback!)
            auto chain_factory_sig = cose::SignatureFactory::FromCryptoSigner(chain_signer);
            
            // Sign with the leaf certificate
            auto chain_signed = chain_factory_sig.SignDirectBytes(
                payload.data(),
                static_cast<uint32_t>(payload.size()),
                "application/chain-example"
            );
            std::cout << "✓ Signed with leaf certificate" << std::endl;
            std::cout << "  Signed message size: " << chain_signed.size() << " bytes" << std::endl;
        }
#else
        std::cout << "\n=== Part 2: Certificate Chain Signing (SKIPPED - feature not available) ===" << std::endl;
#endif

        // ========================================================================
        // Part 3: Post-Quantum Cryptography (ML-DSA-65)
        // ========================================================================
#if defined(COSE_HAS_CERTIFICATES_LOCAL) && defined(COSE_HAS_CRYPTO_OPENSSL) && defined(COSE_HAS_FACTORIES) && defined(COSE_HAS_PQC)
        std::cout << "\n=== Part 3: Post-Quantum Signing (ML-DSA-65) ===" << std::endl;
        
        // Create a PQC certificate with ML-DSA-65
        auto pqc_factory = cose::EphemeralCertificateFactory::New();
        auto pqc_cert = pqc_factory.CreateCertificate(
            "CN=PQC Test Certificate",
            COSE_KEY_ALG_MLDSA,  // ML-DSA algorithm
            65,                   // ML-DSA-65 (security level)
            86400                 // 1 day validity
        );
        std::cout << "✓ Generated ML-DSA-65 certificate" << std::endl;
        std::cout << "  Certificate size: " << pqc_cert.cert_der.size() << " bytes" << std::endl;
        std::cout << "  Private key size: " << pqc_cert.key_der.size() << " bytes" << std::endl;
        
        // Create signer from PQC private key
        auto pqc_crypto = cose::CryptoProvider::New();
        auto pqc_signer = pqc_crypto.SignerFromDer(pqc_cert.key_der);
        std::cout << "✓ Created ML-DSA signer" << std::endl;
        std::cout << "  Algorithm: " << pqc_signer.Algorithm() << " (ML-DSA-65)" << std::endl;
        
        // Create factory DIRECTLY from signer (no callback!)
        auto pqc_factory_sig = cose::SignatureFactory::FromCryptoSigner(pqc_signer);
        
        // Sign with ML-DSA-65
        auto pqc_signed = pqc_factory_sig.SignDirectBytes(
            payload.data(),
            static_cast<uint32_t>(payload.size()),
            "application/pqc-example"
        );
        std::cout << "✓ Created COSE Sign1 message with ML-DSA-65 signature" << std::endl;
        std::cout << "  Total size: " << pqc_signed.size() << " bytes" << std::endl;
        
        // Verify PQC signature
        auto pqc_verifier = pqc_crypto.VerifierFromDer(pqc_cert.cert_der);
        std::cout << "✓ PQC signature verification available" << std::endl;
#else
        std::cout << "\n=== Part 3: Post-Quantum Signing (SKIPPED - feature not available) ===" << std::endl;
        #ifndef COSE_HAS_PQC
        std::cout << "Note: PQC support not enabled. Define COSE_HAS_PQC to enable." << std::endl;
        #endif
#endif

        // ========================================================================
        // Part 4: Streaming Signing (large payload support)
        // ========================================================================
#if defined(COSE_HAS_FACTORIES) && defined(COSE_HAS_CRYPTO_OPENSSL) && defined(COSE_HAS_CERTIFICATES_LOCAL)
        std::cout << "\n=== Part 4: Streaming Signing ===" << std::endl;
        
        // Generate a test file (or use an existing one)
        std::string test_file = "test_payload.bin";
        {
            std::ofstream f(test_file, std::ios::binary);
            std::vector<uint8_t> chunk(65536, 0x42); // 64KB chunks
            for (int i = 0; i < 16; i++) f.write((char*)chunk.data(), chunk.size()); // 1MB file
        }
        std::cout << "✓ Created test file: " << test_file << " (1MB)" << std::endl;
        
        // Sign the file without loading it into memory
        auto stream_cert = cose::EphemeralCertificateFactory::New().CreateSelfSigned();
        auto stream_signer = cose::CryptoProvider::New().SignerFromDer(stream_cert.key_der);
        auto stream_factory = cose::SignatureFactory::FromCryptoSigner(stream_signer);
        
        // File-based streaming sign (detached signature)
        auto detached_sig = stream_factory.SignDirectFile(test_file, "application/octet-stream");
        std::cout << "✓ Streamed 1MB file -> detached signature: " << detached_sig.size() << " bytes" << std::endl;
        std::cout << "  (File was never fully loaded into memory)" << std::endl;
        
        // Callback-based streaming (from any source)
        auto in_memory_data = std::vector<uint8_t>(1024 * 1024, 0xAB); // 1MB
        size_t offset = 0;
        auto reader = [&](uint8_t* buf, size_t len) -> size_t {
            size_t remaining = in_memory_data.size() - offset;
            size_t to_read = std::min(len, remaining);
            std::memcpy(buf, in_memory_data.data() + offset, to_read);
            offset += to_read;
            return to_read;
        };
        auto streamed_sig = stream_factory.SignDirectStreaming(reader, in_memory_data.size(), "application/octet-stream");
        std::cout << "✓ Callback-streamed 1MB -> detached signature: " << streamed_sig.size() << " bytes" << std::endl;
        
        // Cleanup test file
        std::remove(test_file.c_str());
        std::cout << "✓ Cleaned up test file" << std::endl;
#else
        std::cout << "\n=== Part 4: Streaming Signing (SKIPPED - feature not available) ===" << std::endl;
        std::cout << "Requires: COSE_HAS_FACTORIES, COSE_HAS_CRYPTO_OPENSSL, COSE_HAS_CERTIFICATES_LOCAL" << std::endl;
#endif

        // ========================================================================
        // Part 5: Message Inspection (fluent API - RAII cleanup)
        // ========================================================================
#ifdef COSE_HAS_PRIMITIVES
        std::cout << "\n=== Part 5: Message Inspection ===" << std::endl;
        
        if (!signed_bytes.empty()) {
            // Parse the COSE Sign1 message
            // The CoseSign1Message object owns the parsed data and cleans up automatically
            auto msg = cose::CoseSign1Message::Parse(signed_bytes.data(), signed_bytes.size());
            
            // Access protected headers with optional pattern
            auto protected_headers = msg.ProtectedHeaders();
            auto alg = protected_headers.GetInt(COSE_HEADER_ALG);
            if (alg.has_value()) {
                std::cout << "Algorithm: " << alg.value() << std::endl;
            }
            
            auto content_type = protected_headers.GetText(COSE_HEADER_CONTENT_TYPE);
            if (content_type.has_value()) {
                std::cout << "Content Type: " << content_type.value() << std::endl;
            }
            
            // Check payload type
            if (msg.IsDetached()) {
                std::cout << "Payload: <detached>" << std::endl;
            } else {
                auto embedded_payload = msg.Payload();
                if (embedded_payload.has_value()) {
                    std::cout << "Payload: " << embedded_payload->size() << " bytes embedded" << std::endl;
                }
            }
            
            // Access raw signature bytes
            auto signature = msg.Signature();
            std::cout << "Signature: " << signature.size() << " bytes" << std::endl;
        }
#else
        std::cout << "\n=== Part 5: Message Inspection (SKIPPED - feature not available) ===" << std::endl;
#endif

        // ========================================================================
        // Part 6: Validation with Certificates (fluent trust policy API)
        // ========================================================================
#ifdef COSE_HAS_CERTIFICATES_PACK
        std::cout << "\n=== Part 6: Validation with Certificates ===" << std::endl;
        
        if (!signed_bytes.empty()) {
            // Build validator with certificates pack using fluent interface
            cose::ValidatorBuilderWithCertificates builder;
            builder.WithCertificates();
            
            // Create custom trust policy bound to the builder's configured packs
            cose::TrustPolicyBuilder policy(builder);
            
            // Chain multiple policy requirements fluently
            policy.RequireContentTypeNonEmpty();
            
            // Add certificate-specific requirements
            policy.And();
            cose::RequireX509ChainTrusted(policy);
            cose::RequireSigningCertificatePresent(policy);
            cose::RequireSigningCertificateThumbprintPresent(policy);
            
            // Compile the policy into an optimized plan
            auto plan = policy.Compile();
            
            // Attach the compiled plan to the validator builder
            cose::WithCompiledTrustPlan(builder, plan);
            
            // Build the validator (builder is consumed here)
            auto validator = builder.Build();
            
            // Validate the message
            // The ValidationResult object manages its own lifetime
            auto result = validator.Validate(signed_bytes, {});
            
            if (result.Ok()) {
                std::cout << "✓ Validation successful" << std::endl;
            } else {
                std::cout << "✗ Validation failed: " << result.FailureMessage() << std::endl;
            }
        }
#else
        std::cout << "\n=== Part 6: Validation (SKIPPED - certificates pack not available) ===" << std::endl;
#endif

        // ========================================================================
        // Part 7: DID:X509 Operations (fluent API)
        // ========================================================================
#ifdef COSE_HAS_DID_X509
        std::cout << "\n=== Part 7: DID:X509 Operations ===" << std::endl;
        
        // Example certificate data (would normally be loaded from files)
        // Using minimal dummy data for demonstration
        std::vector<uint8_t> leaf_cert = {
            0x30, 0x82, 0x01, 0x00  // Minimal DER certificate header (not valid)
        };
        std::vector<uint8_t> root_cert = {
            0x30, 0x82, 0x01, 0x00  // Minimal DER certificate header (not valid)
        };
        
        // Note: In production, load real DER-encoded X.509 certificates
        try {
            const uint8_t* certs[] = { leaf_cert.data(), root_cert.data() };
            uint32_t lens[] = { 
                static_cast<uint32_t>(leaf_cert.size()), 
                static_cast<uint32_t>(root_cert.size())
            };
            
            // Generate DID:X509 from certificate chain
            // RAII ensures all intermediate strings are cleaned up
            auto did = cose::DidX509BuildFromChain(certs, lens, 2);
            std::cout << "Generated DID:X509: " << did << std::endl;
            
            // Parse and inspect the DID
            // The ParsedDid object manages its lifetime automatically
            auto parsed = cose::DidX509Parse(did);
            std::cout << "DID subjects: " << parsed.SubjectCount() << std::endl;
            std::cout << "Hash algorithm: " << parsed.HashAlgorithm() << std::endl;
            
            // Validate DID against chain
            bool is_valid = cose::DidX509ValidateAgainstChain(did, certs, lens, 2);
            std::cout << "DID validation: " << (is_valid ? "valid" : "invalid") << std::endl;
            
        } catch (const cose::DidX509Error& e) {
            std::cout << "DID:X509 error (expected with dummy data): " << e.what() << std::endl;
        }
#else
        std::cout << "\n=== Part 7: DID:X509 (SKIPPED - feature not available) ===" << std::endl;
#endif

        // ========================================================================
        // Summary: Benefits of C++ RAII API over C API
        // ========================================================================
        std::cout << "\n=== Summary: C++ RAII Advantages ===" << std::endl;
        std::cout << "✓ No manual cleanup - destructors handle resource management" << std::endl;
        std::cout << "✓ No goto statements - exceptions handle error paths" << std::endl;
        std::cout << "✓ Real cryptography - OpenSSL integration for ECDSA and ML-DSA" << std::endl;
        std::cout << "✓ Certificate generation - ephemeral certs and chains" << std::endl;
        std::cout << "✓ Type safety - std::string and std::vector instead of raw pointers" << std::endl;
        std::cout << "✓ Move semantics - zero-copy resource transfer" << std::endl;
        std::cout << "✓ Optional pattern - clear handling of missing values" << std::endl;
        
        return 0;

    } catch (const cose::cose_error& e) {
        std::cerr << "COSE error: " << e.what() << std::endl;
        return 1;
    } catch (const cose::SigningError& e) {
        std::cerr << "Signing error: " << e.what() << std::endl;
        return 1;
    } catch (const cose::primitives_error& e) {
        std::cerr << "Primitives error: " << e.what() << std::endl;
        return 1;
    } catch (const cose::DidX509Error& e) {
        std::cerr << "DID:X509 error: " << e.what() << std::endl;
        return 1;
    } catch (const std::exception& e) {
        std::cerr << "Unexpected error: " << e.what() << std::endl;
        return 1;
    }
}

