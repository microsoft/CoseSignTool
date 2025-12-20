#include "cosesign1/validation/cose_sign1_verifier.h"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "internal/openssl_utils.h"
#include "internal/oqs_utils.h"

#include <cosesign1/common/cbor.h>

namespace cosesign1::validation {

namespace {

using ParsedSign1 = cosesign1::common::cbor::ParsedCoseSign1;

ValidationResult Fail(std::string_view validator_name,
                      std::string message,
                      std::string error_code,
                      std::optional<std::string> property = std::nullopt) {
  ValidationFailure f;
  f.message = std::move(message);
  f.error_code = std::move(error_code);
  f.property_name = std::move(property);
  std::vector<ValidationFailure> failures;
  failures.push_back(std::move(f));
  return ValidationResult::Failure(std::string(validator_name), std::move(failures));
}

std::optional<std::int64_t> ReadAlgFromHeaders(const ParsedSign1& parsed) {
  // COSE rules: protected header parameters are preferred.
  if (const auto prot = parsed.protected_headers.TryGetInt64(1)) {
    return prot;
  }
  return parsed.unprotected_headers.TryGetInt64(1);
}

} // namespace

ValidationResult VerifyCoseSign1(std::string_view validator_name,
                                 const std::vector<std::uint8_t>& cose_sign1,
                                 const VerifyOptions& options) {
  ParsedSign1 parsed;

  std::string parse_error;
  const bool parsed_ok = cosesign1::common::cbor::ParseCoseSign1(cose_sign1, parsed, &parse_error);

  if (!parsed_ok) {
    const std::string msg = parse_error.empty() ? "Invalid COSE_Sign1 structure (CBOR parse failed)"
                                                : ("Invalid COSE_Sign1 structure: " + parse_error);
    return Fail(validator_name, msg, "CBOR_PARSE_ERROR");
  }

  std::optional<std::span<const std::uint8_t>> external_payload;
  std::vector<std::uint8_t> owned_external;
  if (options.external_payload) {
    external_payload = std::span<const std::uint8_t>(options.external_payload->data(), options.external_payload->size());
  } else if (options.external_payload_provider) {
    owned_external = options.external_payload_provider();
    external_payload = std::span<const std::uint8_t>(owned_external.data(), owned_external.size());
  }

  return VerifyParsedCoseSign1(validator_name, parsed, external_payload, options);
}

ValidationResult VerifyParsedCoseSign1(std::string_view validator_name,
                                       const cosesign1::common::cbor::ParsedCoseSign1& parsed,
                                       std::optional<std::span<const std::uint8_t>> external_payload,
                                       const VerifyOptions& options) {

  const auto parsed_alg = ReadAlgFromHeaders(parsed);
  if (!parsed_alg) {
    return Fail(validator_name, "Missing COSE 'alg' header (label 1)", "MISSING_ALG", "alg");
  }

  if (options.expected_alg && static_cast<std::int64_t>(*options.expected_alg) != *parsed_alg) {
    return Fail(validator_name, "COSE 'alg' did not match expected value", "ALG_MISMATCH", "alg");
  }

  std::optional<CoseAlgorithm> alg;
  switch (*parsed_alg) {
    case static_cast<std::int64_t>(CoseAlgorithm::ES256):
      alg = CoseAlgorithm::ES256;
      break;
    case static_cast<std::int64_t>(CoseAlgorithm::ES384):
      alg = CoseAlgorithm::ES384;
      break;
    case static_cast<std::int64_t>(CoseAlgorithm::ES512):
      alg = CoseAlgorithm::ES512;
      break;
    case static_cast<std::int64_t>(CoseAlgorithm::MLDsa44):
      alg = CoseAlgorithm::MLDsa44;
      break;
    case static_cast<std::int64_t>(CoseAlgorithm::MLDsa65):
      alg = CoseAlgorithm::MLDsa65;
      break;
    case static_cast<std::int64_t>(CoseAlgorithm::MLDsa87):
      alg = CoseAlgorithm::MLDsa87;
      break;
    case static_cast<std::int64_t>(CoseAlgorithm::PS256):
      alg = CoseAlgorithm::PS256;
      break;
    case static_cast<std::int64_t>(CoseAlgorithm::RS256):
      alg = CoseAlgorithm::RS256;
      break;
    default:
      return Fail(validator_name, "Unsupported COSE algorithm", "UNSUPPORTED_ALG", "alg");
  }

  std::span<const std::uint8_t> payload_span;
  std::vector<std::uint8_t> owned_external;
  if (parsed.payload) {
    payload_span = std::span<const std::uint8_t>(parsed.payload->data(), parsed.payload->size());
  } else {
    if (!external_payload) {
      if (options.external_payload) {
        external_payload = std::span<const std::uint8_t>(options.external_payload->data(), options.external_payload->size());
      } else if (options.external_payload_provider) {
        owned_external = options.external_payload_provider();
        external_payload = std::span<const std::uint8_t>(owned_external.data(), owned_external.size());
      }
    }
    if (!external_payload) {
      return Fail(validator_name, "Detached payload requires external payload bytes", "MISSING_EXTERNAL_PAYLOAD", "payload");
    }
    payload_span = *external_payload;
  }

  std::optional<std::span<const std::uint8_t>> external_payload_span;
  if (!parsed.payload) {
    external_payload_span = payload_span;
  }

  std::vector<std::uint8_t> tbs;
  (void)cosesign1::common::cbor::EncodeSignature1SigStructure(parsed, external_payload_span, tbs);

  bool ok = false;
  switch (*alg) {
    case CoseAlgorithm::ES256:
    case CoseAlgorithm::ES384:
    case CoseAlgorithm::ES512:
    case CoseAlgorithm::PS256:
    case CoseAlgorithm::RS256: {
      if (!options.public_key_bytes) {
        return Fail(validator_name, "No verification key provided (VerifyOptions.public_key_bytes is required)", "MISSING_KEY");
      }

      auto key = internal::LoadPublicKeyOrCertFromDer(*options.public_key_bytes);
      if (!key) {
        return Fail(validator_name, "Failed to parse public key bytes", "INVALID_PUBLIC_KEY");
      }

      if (*alg == CoseAlgorithm::ES256) {
        ok = internal::VerifyEs256(key.get(), tbs, parsed.signature);
      }
      if (*alg == CoseAlgorithm::ES384) {
        ok = internal::VerifyEs384(key.get(), tbs, parsed.signature);
      }
      if (*alg == CoseAlgorithm::ES512) {
        ok = internal::VerifyEs512(key.get(), tbs, parsed.signature);
      }
      if (*alg == CoseAlgorithm::PS256) {
        ok = internal::VerifyPs256(key.get(), tbs, parsed.signature);
      }
      if (*alg == CoseAlgorithm::RS256) {
        ok = internal::VerifyRs256(key.get(), tbs, parsed.signature);
      }
      break;
    }
    case CoseAlgorithm::MLDsa44:
    case CoseAlgorithm::MLDsa65:
    case CoseAlgorithm::MLDsa87: {
#if defined(COSESIGN1_ENABLE_PQC)
      if (!options.public_key_bytes) {
        return Fail(validator_name, "No PQC verification key provided (set VerifyOptions.public_key_bytes)", "MISSING_KEY");
      }

      ok = internal::VerifyMlDsa(static_cast<std::int64_t>(*alg), tbs, parsed.signature, *options.public_key_bytes);
#else
      (void)tbs;
      return Fail(validator_name, "PQC algorithms are not enabled in this build", "PQC_DISABLED", "alg");
#endif
      break;
    }
  }

  if (!ok) {
    return Fail(validator_name, "Signature verification failed", "SIGNATURE_INVALID");
  }

  std::unordered_map<std::string, std::string> metadata;
  metadata.emplace("alg", std::to_string(*parsed_alg));
  metadata.emplace("payloadLength", std::to_string(payload_span.size()));
  return ValidationResult::Success(std::string(validator_name), std::move(metadata));
}

} // namespace cosesign1::validation
