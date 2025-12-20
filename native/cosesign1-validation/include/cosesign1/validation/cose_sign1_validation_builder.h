// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <memory>
#include <optional>
#include <span>
#include <utility>
#include <vector>

#include "cosesign1/validation/composite_cose_sign1_validator.h"
#include "cosesign1/validation/cose_sign1_signature_validator.h"
#include "cosesign1/validation/cose_sign1_validation_builder_context.h"
#include "cosesign1/validation/cose_sign1_validation_context.h"
#include "cosesign1/validation/i_cose_sign1_validator.h"

namespace cosesign1::validation {

/**
 * @file cose_sign1_validation_builder.h
 * @brief Fluent builder for constructing and running COSE_Sign1 validation pipelines.
 */

/**
 * @brief Builds a CompositeCoseSign1Validator using a fluent API.
 */
class CoseSign1ValidationBuilder final {
 public:
  /**
   * @brief Adds a validator to the pipeline.
   * @throws std::invalid_argument if @p validator is null.
   */
  CoseSign1ValidationBuilder& AddValidator(std::shared_ptr<ICoseSign1Validator> validator);

  /**
   * @brief When enabled, stops at the first failure.
   */
  CoseSign1ValidationBuilder& StopOnFirstFailure(bool enabled = true);

  /**
   * @brief When enabled, runs non-"last" validators concurrently.
   */
  CoseSign1ValidationBuilder& RunInParallel(bool enabled = true);

  /**
   * @brief Produces the immutable composite validator.
   */
  CompositeCoseSign1Validator Build() const;

  /**
   * @brief Runs all registered validators against a pre-parsed COSE_Sign1.
   */
  ValidationResult Validate(const ParsedCoseSign1& parsed,
                            std::optional<std::span<const std::uint8_t>> external_payload = std::nullopt,
                            VerifyOptions::BytesProvider external_payload_provider = {}) const;

 private:
  std::vector<std::shared_ptr<ICoseSign1Validator>> validators_;
  CoseSign1ValidationBuilderContext context_;
};

} // namespace cosesign1::validation
