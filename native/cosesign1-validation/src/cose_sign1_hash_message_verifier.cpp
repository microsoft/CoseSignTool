// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file cose_sign1_hash_message_verifier.cpp
 * @brief Implementation of CoseSign1HashMessageVerifier.
 */

#include "cosesign1/validation/cose_sign1_hash_message_verifier.h"

#include <algorithm>

namespace cosesign1::validation {

namespace {
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

std::optional<std::vector<std::uint8_t>> ComputeDigest(const EVP_MD* md, std::span<const std::uint8_t> data) {
  if (!md) return std::nullopt;

  MdCtxPtr ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
  if (!ctx) return std::nullopt;

  if (EVP_DigestInit_ex(ctx.get(), md, nullptr) != 1) return std::nullopt;
  if (!data.empty()) {
    if (EVP_DigestUpdate(ctx.get(), data.data(), data.size()) != 1) return std::nullopt;
  }

  unsigned int out_len = EVP_MD_size(md);
  if (out_len == 0U) return std::nullopt;

  std::vector<std::uint8_t> out(static_cast<std::size_t>(out_len));
  if (EVP_DigestFinal_ex(ctx.get(), out.data(), &out_len) != 1) return std::nullopt;
  out.resize(static_cast<std::size_t>(out_len));
  return out;
}

} // namespace

const EVP_MD* CoseSign1HashMessageVerifier::GetDigestForCoseHashAlg(std::int64_t cose_hash_alg) {
  // Values are from the IANA COSE Algorithms registry.
  // SHA-256 = -16, SHA-384 = -43, SHA-512 = -44.
  switch (cose_hash_alg) {
    case -16:
      return EVP_sha256();
    case -43:
      return EVP_sha384();
    case -44:
      return EVP_sha512();
    default:
      return nullptr;
  }
}

ValidationResult CoseSign1HashMessageVerifier::Validate(const ParsedCoseSign1& input,
                                                       const CoseSign1ValidationContext& context) const {
  static constexpr const char* kName = "CoseSign1HashMessageVerifier";

  // Enforce draft rules: payload-hash-alg must be protected-only.
  if (input.unprotected_headers.Contains(kCoseHashEnvelopePayloadHashAlgLabel)) {
    return ValidationResult::Failure(kName,
                                    "payload-hash-alg (258) MUST NOT be present in unprotected headers",
                                    "cosehash.payload_hash_alg_unprotected");
  }

  const auto cose_hash_alg = input.protected_headers.TryGetInt64(kCoseHashEnvelopePayloadHashAlgLabel);
  if (!cose_hash_alg.has_value()) {
    return ValidationResult::Failure(kName,
                                    "payload-hash-alg (258) was not present in protected headers",
                                    "cosehash.payload_hash_alg_missing");
  }

  const EVP_MD* md = GetDigestForCoseHashAlg(*cose_hash_alg);
  if (!md) {
    return ValidationResult::Failure(kName,
                                    "payload-hash-alg is not supported",
                                    "cosehash.payload_hash_alg_unsupported");
  }

  if (!input.payload.has_value() || input.payload->empty()) {
    return ValidationResult::Failure(kName,
                                    "COSE_Sign1 payload did not contain an embedded hash payload",
                                    "cosehash.embedded_hash_missing");
  }

  std::optional<std::span<const std::uint8_t>> external = context.external_payload;
  std::vector<std::uint8_t> owned_external;
  if (!external.has_value()) {
    if (payload_provider_) {
      owned_external = payload_provider_();
      external = std::span<const std::uint8_t>(owned_external.data(), owned_external.size());
    } else if (context.external_payload_provider) {
      owned_external = context.external_payload_provider();
      external = std::span<const std::uint8_t>(owned_external.data(), owned_external.size());
    }
  }

  if (!external.has_value()) {
    return ValidationResult::Failure(kName,
                                    "external payload bytes are required to validate the embedded hash",
                                    "cosehash.external_payload_missing");
  }

  const auto digest = ComputeDigest(md, *external);
  if (!digest.has_value()) {
    return ValidationResult::Failure(kName,
                                    "failed to compute payload hash",
                                    "cosehash.hash_compute_failed");
  }

  const auto embedded = std::span<const std::uint8_t>(input.payload->data(), input.payload->size());
  if (embedded.size() != digest->size() || !std::equal(embedded.begin(), embedded.end(), digest->begin())) {
    return ValidationResult::Failure(kName,
                                    "payload hash did not match embedded hash",
                                    "cosehash.payload_hash_mismatch");
  }

  return ValidationResult::Success(kName, {{"payload_hash_alg", std::to_string(*cose_hash_alg)}});
}

} // namespace cosesign1::validation
