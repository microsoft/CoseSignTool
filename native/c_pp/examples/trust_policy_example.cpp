// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#include <cose/trust.hpp>

#ifdef COSE_HAS_CERTIFICATES_PACK
#include <cose/certificates.hpp>
#endif

#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

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
        << "Notes:\n"
        << "- Builds a custom trust policy, compiles it to a bundled plan, attaches it to the builder,\n"
        << "  then validates the message and prints a failure message.\n";
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

    if (has_payload) {
        if (!read_file_bytes(payload_path, payload_bytes)) {
            std::cerr << "Failed to read detached payload file: " << payload_path << "\n";
            return 2;
        }
    }

    try {
#ifdef COSE_HAS_CERTIFICATES_PACK
        // 1) Builder + packs
        cose::ValidatorBuilderWithCertificates builder;
        builder.WithCertificates();
#else
        cose::ValidatorBuilder builder;
#endif

        // 2) Custom trust policy bound to builder's configured packs
        cose::TrustPolicyBuilder policy(builder);

        if (has_payload) {
            policy.RequireDetachedPayloadPresent();
        } else {
            policy.RequireDetachedPayloadAbsent();
        }

#ifdef COSE_HAS_CERTIFICATES_PACK
        // Pack-specific trust-policy helpers (certificates pack)
        policy.And();
        cose::RequireX509ChainTrusted(policy);
        cose::RequireSigningCertificatePresent(policy);
        cose::RequireSigningCertificateThumbprintPresent(policy);
#endif

        // 3) Compile + attach
        auto plan = policy.Compile();
        cose::WithCompiledTrustPlan(builder, plan);

        // 4) Build validator
        auto validator = builder.Build();

        // 5) Validate
        auto result = validator.Validate(cose_bytes, payload_bytes);
        if (result.Ok()) {
            std::cout << "Validation successful\n";
            return 0;
        }

        std::cout << "Validation failed: " << result.FailureMessage() << "\n";
        return 1;
    } catch (const cose::cose_error& e) {
        std::cerr << "Error: " << e.what() << "\n";
        return 3;
    }
}
