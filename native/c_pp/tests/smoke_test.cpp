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
