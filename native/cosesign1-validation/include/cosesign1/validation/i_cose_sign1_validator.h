// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <cosesign1/common/cbor.h>

#include "cosesign1/validation/cose_sign1_validation_context.h"
#include "cosesign1/validation/validation_result.h"

namespace cosesign1::validation {

/**
 * @file i_cose_sign1_validator.h
 * @brief Interface for a single COSE_Sign1 validation rule.
 */

/**
 * @brief Alias used across the validation API for the parsed COSE_Sign1 model.
 */
using ParsedCoseSign1 = cosesign1::common::cbor::ParsedCoseSign1;

/**
 * @brief Validates a parsed COSE_Sign1 message.
 *
 * Implementations should be pure and deterministic with respect to their inputs.
 * Any expensive work should be bounded and expressed as a ValidationFailure rather
 * than throwing, except for programmer errors (e.g. null pointers passed to builder).
 */
class ICoseSign1Validator {
 public:
  virtual ~ICoseSign1Validator() = default;

  /**
   * @brief Validates @p input using the supplied @p context.
   * @return A ValidationResult indicating success or failure.
   */
  virtual ValidationResult Validate(const ParsedCoseSign1& input, const CoseSign1ValidationContext& context) const = 0;
};

} // namespace cosesign1::validation
