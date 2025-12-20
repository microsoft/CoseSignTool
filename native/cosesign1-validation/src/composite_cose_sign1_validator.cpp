// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file composite_cose_sign1_validator.cpp
 * @brief Implementation of CompositeCoseSign1Validator.
 */

#include "cosesign1/validation/composite_cose_sign1_validator.h"

#include <future>
#include <string>
#include <unordered_map>
#include <utility>

#include "cosesign1/validation/validator_markers.h"

namespace cosesign1::validation {

CompositeCoseSign1Validator::CompositeCoseSign1Validator(std::vector<std::shared_ptr<ICoseSign1Validator>> validators,
                                                         CoseSign1ValidationBuilderContext context)
    : validators_(std::move(validators)), context_(context) {}

ValidationResult CompositeCoseSign1Validator::Validate(const ParsedCoseSign1& input,
                                                       const CoseSign1ValidationContext& context) const {
  static constexpr const char* kName = "CompositeCoseSign1Validator";

  if (validators_.empty()) {
    return ValidationResult::Success(kName);
  }

  // Partition validators into normal vs "must run last".
  std::vector<std::shared_ptr<ICoseSign1Validator>> non_last;
  std::vector<std::shared_ptr<ICoseSign1Validator>> last;
  non_last.reserve(validators_.size());
  last.reserve(validators_.size());
  for (const auto& validator : validators_) {
    if (dynamic_cast<ILastCoseSign1Validator*>(validator.get()) != nullptr) {
      last.push_back(validator);
    } else {
      non_last.push_back(validator);
    }
  }

  std::vector<ValidationFailure> all_failures;
  std::vector<ValidationResult> results;
  results.reserve(validators_.size());

  if (context_.run_in_parallel) {
    std::vector<std::future<ValidationResult>> futures;
    futures.reserve(non_last.size());
    for (const auto& validator : non_last) {
      futures.push_back(std::async(std::launch::async, [&input, &context, validator]() {
        return validator->Validate(input, context);
      }));
    }

    for (auto& f : futures) {
      auto r = f.get();
      results.push_back(r);
      if (!r.is_valid) {
        all_failures.insert(all_failures.end(), r.failures.begin(), r.failures.end());
      }
    }
  } else {
    for (const auto& validator : non_last) {
      auto r = validator->Validate(input, context);
      results.push_back(r);

      if (!r.is_valid) {
        all_failures.insert(all_failures.end(), r.failures.begin(), r.failures.end());
        if (context_.stop_on_first_failure) {
          break;
        }
      }
    }
  }

  // Only run "must run last" validators if everything else passed.
  if (all_failures.empty()) {
    for (const auto& validator : last) {
      auto r = validator->Validate(input, context);
      results.push_back(r);

      if (!r.is_valid) {
        all_failures.insert(all_failures.end(), r.failures.begin(), r.failures.end());
        if (context_.stop_on_first_failure) {
          break;
        }
      }
    }
  }

  if (!all_failures.empty()) {
    return ValidationResult::Failure(kName, std::move(all_failures));
  }

  std::unordered_map<std::string, std::string> merged;
  for (const auto& r : results) {
    for (const auto& kv : r.metadata) {
      merged.emplace(r.validator_name + "." + kv.first, kv.second);
    }
  }

  return ValidationResult::Success(kName, std::move(merged));
}

} // namespace cosesign1::validation
