// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file cose_sign1_validation_builder.cpp
 * @brief Implementation of CoseSign1ValidationBuilder.
 */
#include "cosesign1/validation/cose_sign1_validation_builder.h"

#include <stdexcept>
#include <utility>

namespace cosesign1::validation {

CoseSign1ValidationBuilder& CoseSign1ValidationBuilder::AddValidator(std::shared_ptr<ICoseSign1Validator> validator) {
  if (!validator) {
    throw std::invalid_argument("validator");
  }
  validators_.push_back(std::move(validator));
  return *this;
}

CoseSign1ValidationBuilder& CoseSign1ValidationBuilder::StopOnFirstFailure(bool enabled) {
  context_.stop_on_first_failure = enabled;
  return *this;
}

CoseSign1ValidationBuilder& CoseSign1ValidationBuilder::RunInParallel(bool enabled) {
  context_.run_in_parallel = enabled;
  return *this;
}

CompositeCoseSign1Validator CoseSign1ValidationBuilder::Build() const {
  return CompositeCoseSign1Validator(validators_, context_);
}

ValidationResult CoseSign1ValidationBuilder::Validate(const ParsedCoseSign1& parsed,
                                                      std::optional<std::span<const std::uint8_t>> external_payload,
                                                      VerifyOptions::BytesProvider external_payload_provider) const {
  CoseSign1ValidationContext ctx;
  ctx.external_payload = external_payload;
  ctx.external_payload_provider = std::move(external_payload_provider);
  return Build().Validate(parsed, ctx);
}

} // namespace cosesign1::validation
