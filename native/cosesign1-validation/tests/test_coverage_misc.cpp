// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file test_coverage_misc.cpp
 * @brief Tests that exercise hard-to-reach coverage paths.
 */

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <stdexcept>
#include <vector>

#include "cosesign1/validation/cose_sign1_verifier.h"
#include "cosesign1/validation/cose_sign1_validation_builder.h"
#include "cosesign1/validation/validator.h"
#include "cosesign1/validation/validator_markers.h"

#include "test_utils.h"

#include "../src/internal/openssl_utils.h"
#include "../src/internal/coverage_hooks.h"

#if defined(COSESIGN1_ENABLE_PQC)
#include "../src/internal/oqs_utils.h"
#endif

namespace {

bool HasErrorCode(const cosesign1::validation::ValidationResult& r, const char* code) {
  for (const auto& f : r.failures) {
    if (f.error_code && *f.error_code == code) return true;
  }
  return false;
}

} // namespace

TEST_CASE("IValidator virtual destructor executes") {
  struct V final : cosesign1::validation::IValidator<int> {
    cosesign1::validation::ValidationResult Validate(const int&) const override {
      return cosesign1::validation::ValidationResult::Success("V");
    }
    ~V() override = default;
  };

  cosesign1::validation::IValidator<int>* v = new V();
  delete v;
  SUCCEED();
}

TEST_CASE("ILastCoseSign1Validator virtual destructor executes") {
  struct V final : cosesign1::validation::ILastCoseSign1Validator {
    ~V() override = default;
  };

  cosesign1::validation::ILastCoseSign1Validator* v = new V();
  delete v;
  SUCCEED();
}

TEST_CASE("ICoseSign1Validator virtual destructor executes") {
  struct V final : cosesign1::validation::ICoseSign1Validator {
    cosesign1::validation::ValidationResult Validate(const cosesign1::validation::ParsedCoseSign1&,
                                                     const cosesign1::validation::CoseSign1ValidationContext&) const override {
      return cosesign1::validation::ValidationResult::Success("V");
    }
    ~V() override = default;
  };

  cosesign1::validation::ICoseSign1Validator* v = new V();
  delete v;
  SUCCEED();
}

TEST_CASE("LoadPublicKeyOrCertFromPem returns null on empty input") {
  // BIO_new_mem_buf may fail on empty input; cover the !bio early-return.
  const auto key = cosesign1::internal::LoadPublicKeyOrCertFromPem(std::string());
  REQUIRE_FALSE(static_cast<bool>(key));
}

TEST_CASE("VerifyCoseSign1 ML-DSA-65 hits verifier branch") {
  constexpr std::int64_t alg = -49; // ML-DSA-65

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(alg);
  const std::vector<std::uint8_t> payload = {1, 2, 3};

  const std::vector<std::uint8_t> sig = {0x01};
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::MLDsa65;

#if defined(COSESIGN1_ENABLE_PQC)
  // Provide a deliberately wrong-size public key so we exercise liboqs mapping/size checks.
  opt.public_key_bytes = std::vector<std::uint8_t>(1, 0x00);
  const auto r = cosesign1::validation::VerifyCoseSign1("SigValidator", cose, opt);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "SIGNATURE_INVALID"));
#else
  const auto r = cosesign1::validation::VerifyCoseSign1("SigValidator", cose, opt);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "PQC_DISABLED"));
#endif
}

TEST_CASE("VerifyCoseSign1 ML-DSA-87 hits verifier branch") {
  constexpr std::int64_t alg = -50; // ML-DSA-87

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(alg);
  const std::vector<std::uint8_t> payload = {4, 5, 6};

  const std::vector<std::uint8_t> sig = {0x01};
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::MLDsa87;

#if defined(COSESIGN1_ENABLE_PQC)
  opt.public_key_bytes = std::vector<std::uint8_t>(1, 0x00);
  const auto r = cosesign1::validation::VerifyCoseSign1("SigValidator", cose, opt);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "SIGNATURE_INVALID"));
#else
  const auto r = cosesign1::validation::VerifyCoseSign1("SigValidator", cose, opt);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "PQC_DISABLED"));
#endif
}

TEST_CASE("Coverage hooks: validation headers are executed in library") {
  cosesign1::internal::RunCoverageHooks_ValidationHeaders();
  SUCCEED();
}

#if defined(COSESIGN1_ENABLE_PQC)

TEST_CASE("VerifyMlDsa rejects unsupported COSE alg") {
  const std::vector<std::uint8_t> empty;
  REQUIRE_FALSE(cosesign1::internal::VerifyMlDsa(12345, empty, empty, empty));
}

TEST_CASE("VerifyMlDsa rejects wrong sizes for ML-DSA-65") {
  const std::vector<std::uint8_t> empty;
  REQUIRE_FALSE(cosesign1::internal::VerifyMlDsa(-49, empty, empty, empty));
}

TEST_CASE("VerifyMlDsa rejects wrong sizes for ML-DSA-87") {
  const std::vector<std::uint8_t> empty;
  REQUIRE_FALSE(cosesign1::internal::VerifyMlDsa(-50, empty, empty, empty));
}

#endif
