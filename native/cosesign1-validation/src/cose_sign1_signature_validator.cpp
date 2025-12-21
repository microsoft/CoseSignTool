// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file cose_sign1_signature_validator.cpp
 * @brief Implementation of CoseSign1SignatureValidator.
 */

#include "cosesign1/validation/cose_sign1_signature_validator.h"

#include <optional>
#include <span>
#include <utility>

namespace cosesign1::validation {

CoseSign1SignatureValidator::CoseSign1SignatureValidator(std::string validator_name, VerifyOptions options)
    : validator_name_(std::move(validator_name)), options_(std::move(options)) {}

ValidationResult CoseSign1SignatureValidator::Validate(const ParsedCoseSign1& input,
                                                       const CoseSign1ValidationContext& context) const {
  std::optional<std::span<const std::uint8_t>> ext = context.external_payload;
  if (!ext && options_.external_payload) {
    ext = std::span<const std::uint8_t>(options_.external_payload->data(), options_.external_payload->size());
  }

  if (!ext && context.external_payload_provider) {
    // Materialize bytes for signature verification.
    owned_external_payload_ = context.external_payload_provider();
    ext = std::span<const std::uint8_t>(owned_external_payload_.data(), owned_external_payload_.size());
  }

  if (!ext && options_.external_payload_provider) {
    owned_external_payload_ = options_.external_payload_provider();
    ext = std::span<const std::uint8_t>(owned_external_payload_.data(), owned_external_payload_.size());
  }
  return VerifyParsedCoseSign1(validator_name_, input, ext, options_);
}

} // namespace cosesign1::validation
