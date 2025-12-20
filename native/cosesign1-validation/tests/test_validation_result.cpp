// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file test_validation_result.cpp
 * @brief Unit tests for ValidationResult.
 */

#include <catch2/catch_test_macros.hpp>

#include "cosesign1/validation/validation_result.h"

namespace {
using cosesign1::validation::ValidationFailure;
using cosesign1::validation::ValidationResult;
} // namespace

TEST_CASE("ValidationResult::Success sets defaults") {
  auto r = ValidationResult::Success("TestValidator");
  REQUIRE(r.is_valid);
  REQUIRE(r.validator_name == "TestValidator");
  REQUIRE(r.failures.empty());
  REQUIRE(r.metadata.empty());
}

TEST_CASE("ValidationResult::Failure single failure") {
  auto r = ValidationResult::Failure("TestValidator", "Error message", "ERROR_CODE");
  REQUIRE(!r.is_valid);
  REQUIRE(r.validator_name == "TestValidator");
  REQUIRE(r.failures.size() == 1);
  REQUIRE(r.failures[0].message == "Error message");
  REQUIRE(r.failures[0].error_code.has_value());
  REQUIRE(*r.failures[0].error_code == "ERROR_CODE");
}

TEST_CASE("ValidationResult::Failure multiple failures") {
  std::vector<ValidationFailure> failures;
  failures.push_back(ValidationFailure{.message = "Error 1", .error_code = std::string("ERR1")});
  failures.push_back(ValidationFailure{.message = "Error 2", .error_code = std::string("ERR2")});

  auto r = ValidationResult::Failure("TestValidator", std::move(failures));
  REQUIRE(!r.is_valid);
  REQUIRE(r.failures.size() == 2);
  REQUIRE(r.failures[0].message == "Error 1");
  REQUIRE(r.failures[1].message == "Error 2");
}
