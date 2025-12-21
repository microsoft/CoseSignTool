// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file test_verify_bad_signature.cpp
 * @brief Verification tests for invalid signatures.
 */

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <vector>

#include "cosesign1/validation/cose_sign1_verifier.h"
#include "test_utils.h"

TEST_CASE("VerifyCoseSign1 bad signature fails") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  auto der = cosesign1::tests::PublicKeyDerFromKey(key.get());

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-7);
  const std::vector<std::uint8_t> payload = {1, 1, 2, 3};

  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);
  sig[0] ^= 0xFF;

  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.public_key_bytes = std::move(der);

  auto r = cosesign1::validation::VerifyCoseSign1("SigValidator", cose, opt);
  REQUIRE(!r.is_valid);
}
