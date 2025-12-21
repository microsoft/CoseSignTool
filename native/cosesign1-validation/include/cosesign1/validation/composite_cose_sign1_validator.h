// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <memory>
#include <vector>

#include "cosesign1/validation/cose_sign1_validation_builder_context.h"
#include "cosesign1/validation/i_cose_sign1_validator.h"

namespace cosesign1::validation {

/**
 * @file composite_cose_sign1_validator.h
 * @brief Aggregates a set of validators into a single validator.
 */

/**
 * @brief Runs a list of validators as a single unit.
 *
 * Responsibilities:
 * - Execute validators either sequentially or in parallel (best-effort).
 * - Aggregate all ValidationFailures (or stop early if configured).
 * - Ensure ILastCoseSign1Validator validators run last and only when all others succeed.
 */
class CompositeCoseSign1Validator final {
 public:
  /**
   * @brief Creates a composite validator.
   * @param validators Ordered list of validators to execute.
   * @param context Execution behavior knobs.
   */
  explicit CompositeCoseSign1Validator(std::vector<std::shared_ptr<ICoseSign1Validator>> validators,
                                      CoseSign1ValidationBuilderContext context);

  /**
   * @brief Runs all validators and returns a merged ValidationResult.
   */
  ValidationResult Validate(const ParsedCoseSign1& input, const CoseSign1ValidationContext& context) const;

 private:
  std::vector<std::shared_ptr<ICoseSign1Validator>> validators_;
  CoseSign1ValidationBuilderContext context_;
};

} // namespace cosesign1::validation
