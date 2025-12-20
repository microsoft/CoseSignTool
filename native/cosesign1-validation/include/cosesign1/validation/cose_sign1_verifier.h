#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <cosesign1/common/cbor.h>

#include "cosesign1/validation/validation_result.h"

namespace cosesign1::validation {

enum class CoseAlgorithm : std::int64_t {
  ES256 = -7,
  ES384 = -35,
  ES512 = -36,
  // Provisional COSE algorithm IDs used by this repo for ML-DSA (post-quantum).
  // -48: ML-DSA-44 (128-bit security)
  // -49: ML-DSA-65 (192-bit security)
  // -50: ML-DSA-87 (256-bit security)
  MLDsa44 = -48,
  MLDsa65 = -49,
  MLDsa87 = -50,
  PS256 = -37,
  RS256 = -257,
};

struct VerifyOptions {
  using BytesProvider = std::function<std::vector<std::uint8_t>()>;

  // If the COSE_Sign1 payload is null (detached payload), provide the external payload here.
  std::optional<std::vector<std::uint8_t>> external_payload;

  // Alternative to external_payload: provides the payload bytes on demand.
  // This is intended for stream-backed payloads; the provider should return the full payload bytes.
  // The provider may be called more than once by different validators.
  BytesProvider external_payload_provider;

  // Public key bytes (algorithm-specific):
  // - For ECDSA/RSA/RSASSA-PSS: DER-encoded SubjectPublicKeyInfo or DER-encoded X.509 certificate.
  // - For PQC (ML-DSA): raw public key bytes (as required by liboqs).
  std::optional<std::vector<std::uint8_t>> public_key_bytes;

  // If provided, require the COSE alg header to match.
  std::optional<CoseAlgorithm> expected_alg;
};

ValidationResult VerifyCoseSign1(std::string_view validator_name,
                                 const std::vector<std::uint8_t>& cose_sign1,
                                 const VerifyOptions& options);

// Verifies a COSE_Sign1 that has already been parsed into a ParsedCoseSign1.
//
// If the message payload is detached (payload is null), provide the external payload bytes via `external_payload`.
ValidationResult VerifyParsedCoseSign1(
  std::string_view validator_name,
  const cosesign1::common::cbor::ParsedCoseSign1& parsed,
  std::optional<std::span<const std::uint8_t>> external_payload,
  const VerifyOptions& options);

} // namespace cosesign1::validation
