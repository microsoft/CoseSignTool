#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <vector>

#include <openssl/evp.h>

#include <cosesign1/common/cbor.h>

#include "cosesign1/validation/cose_sign1_validation_builder.h"
#include "cosesign1/validation/validation_result.h"
#include "cosesign1/validation/validator_markers.h"

namespace cosesign1::validation {

// COSE Hash Envelope (draft-ietf-cose-hash-envelope) protected header label.
inline constexpr std::int64_t kCoseHashEnvelopePayloadHashAlgLabel = 258;

// Verifies a COSE Hash Envelope-style embedded message payload hash.
//
// This verifier expects:
// - The COSE_Sign1 payload to be an embedded hash (i.e. ParsedCoseSign1::payload has value)
// - The external payload bytes to be supplied either via the validation context
//   (CoseSign1ValidationContext::external_payload) or via the payload provider.
// - The protected header label 258 (payload-hash-alg) to be present.
//
// It computes hash(external_payload) using the indicated algorithm and compares it
// against the embedded hash payload.
class CoseSign1HashMessageVerifier final : public ICoseSign1Validator, public ILastCoseSign1Validator {
 public:
  using PayloadProvider = std::function<std::vector<std::uint8_t>()>;

  // Uses external payload bytes provided via CoseSign1ValidationContext::external_payload.
  CoseSign1HashMessageVerifier() = default;

  // Uses external payload bytes provided by the callback. This enables stream-backed payloads.
  explicit CoseSign1HashMessageVerifier(PayloadProvider payload_provider) : payload_provider_(std::move(payload_provider)) {}

  ValidationResult Validate(const ParsedCoseSign1& input, const CoseSign1ValidationContext& context) const override;

 private:
  static const EVP_MD* GetDigestForCoseHashAlg(std::int64_t cose_hash_alg);

  PayloadProvider payload_provider_;
};

} // namespace cosesign1::validation
