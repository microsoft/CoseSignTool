// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/**
 * @file validation_result.h
 * @brief Standard result type returned by validators.
 */

#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "cosesign1/validation/validation_failure.h"

namespace cosesign1::validation {

struct ValidationResult {
  bool is_valid = false;
  std::string validator_name;
  std::vector<ValidationFailure> failures;
  std::unordered_map<std::string, std::string> metadata;

  static ValidationResult Success(
      std::string validator_name,
      std::unordered_map<std::string, std::string> metadata = {}) {
    ValidationResult r;
    r.is_valid = true;
    r.validator_name = std::move(validator_name);
    r.metadata = std::move(metadata);
    return r;
  }

  static ValidationResult Failure(std::string validator_name, std::vector<ValidationFailure> failures) {
    ValidationResult r;
    r.is_valid = false;
    r.validator_name = std::move(validator_name);
    r.failures = std::move(failures);
    return r;
  }

  static ValidationResult Failure(
      std::string validator_name,
      std::string message,
      std::optional<std::string> error_code = std::nullopt) {
    ValidationFailure f;
    f.message = std::move(message);
    f.error_code = std::move(error_code);
    std::vector<ValidationFailure> failures;
    failures.push_back(std::move(f));
    return Failure(std::move(validator_name), std::move(failures));
  }
};

} // namespace cosesign1::validation
