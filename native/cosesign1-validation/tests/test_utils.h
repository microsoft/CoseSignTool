// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file test_utils.h
 * @brief Test helper declarations.
 */

#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include <tinycbor/cbor.h>

namespace cosesign1::tests {

std::string PublicKeyPemFromKey(EVP_PKEY* key);
std::vector<std::uint8_t> PublicKeyDerFromKey(EVP_PKEY* key);

std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> GenerateEcP256Key();
std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> GenerateRsaKey(int bits);

std::vector<std::uint8_t> MakeProtectedHeaderAlg(std::int64_t alg);
std::vector<std::uint8_t> MakeCoseSign1(
    const std::vector<std::uint8_t>& protected_header_bstr,
    bool payload_is_detached,
    std::span<const std::uint8_t> payload,
    std::span<const std::uint8_t> signature);

std::vector<std::uint8_t> BuildSigStructure(
    const std::vector<std::uint8_t>& protected_header_bstr,
    std::span<const std::uint8_t> payload);

// Sign the COSE Sig_structure bytes with ES256 and return the COSE raw signature r||s.
std::vector<std::uint8_t> SignEs256ToCoseRaw(EVP_PKEY* key, std::span<const std::uint8_t> to_be_signed);

// Sign the COSE Sig_structure bytes with PS256 and return signature bytes.
std::vector<std::uint8_t> SignPs256(EVP_PKEY* key, std::span<const std::uint8_t> to_be_signed);

#if defined(COSESIGN1_ENABLE_PQC)
struct OqsKeyPair {
    std::vector<std::uint8_t> public_key;
    std::vector<std::uint8_t> secret_key;
};

OqsKeyPair GenerateMlDsaKeyPair(std::int64_t cose_alg);
std::vector<std::uint8_t> SignMlDsa(std::int64_t cose_alg,
                                                                        std::span<const std::uint8_t> to_be_signed,
                                                                        std::span<const std::uint8_t> secret_key);
#endif

} // namespace cosesign1::tests
