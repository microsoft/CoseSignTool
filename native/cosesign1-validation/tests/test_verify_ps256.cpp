// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file test_verify_ps256.cpp
 * @brief Verification tests for PS256.
 */

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <vector>

#include "cosesign1/validation/cose_sign1_verifier.h"
#include "test_utils.h"

TEST_CASE("VerifyCoseSign1 PS256 succeeds") {
  auto key = cosesign1::tests::GenerateRsaKey(2048);
  auto der = cosesign1::tests::PublicKeyDerFromKey(key.get());

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-37);
  const std::vector<std::uint8_t> payload = {0, 1, 2, 3, 4, 5, 6};

  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = cosesign1::tests::SignPs256(key.get(), tbs);
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.public_key_bytes = std::move(der);
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::PS256;

  auto r = cosesign1::validation::VerifyCoseSign1("SigValidator", cose, opt);
  REQUIRE(r.is_valid);
}
