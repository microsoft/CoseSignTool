// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file test_verify_detached_payload.cpp
 * @brief Verification tests for detached payload behavior.
 */

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

#include <cosesign1/common/cbor.h>

#include "cosesign1/validation/cose_sign1_verifier.h"
#include "test_utils.h"

TEST_CASE("VerifyCoseSign1 detached payload succeeds") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  auto der = cosesign1::tests::PublicKeyDerFromKey(key.get());

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-7);
  const std::vector<std::uint8_t> payload = {9, 8, 7, 6, 5, 4};

  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);

  // payload is detached => encoded as null
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, true, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.public_key_bytes = std::move(der);
  opt.external_payload = payload;

  auto r = cosesign1::validation::VerifyCoseSign1("SigValidator", cose, opt);
  REQUIRE(r.is_valid);
}

TEST_CASE("VerifyCoseSign1 detached payload missing external fails") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  auto der = cosesign1::tests::PublicKeyDerFromKey(key.get());

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-7);
  const std::vector<std::uint8_t> payload = {9, 8, 7, 6};

  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, true, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.public_key_bytes = std::move(der);

  auto r = cosesign1::validation::VerifyCoseSign1("SigValidator", cose, opt);
  REQUIRE(!r.is_valid);
  REQUIRE(!r.failures.empty());
}

TEST_CASE("VerifyCoseSign1 detached payload succeeds with external_payload_provider") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  auto der = cosesign1::tests::PublicKeyDerFromKey(key.get());

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-7);
  const std::vector<std::uint8_t> payload = {5, 4, 3, 2, 1};

  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);

  // payload is detached => encoded as null
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, true, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.public_key_bytes = std::move(der);
  opt.external_payload_provider = [payload]() { return payload; };

  auto r = cosesign1::validation::VerifyCoseSign1("SigValidator", cose, opt);
  REQUIRE(r.is_valid);
}

TEST_CASE("VerifyParsedCoseSign1 detached payload uses options.external_payload when external not passed") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  auto der = cosesign1::tests::PublicKeyDerFromKey(key.get());

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-7);
  const std::vector<std::uint8_t> payload = {9, 8, 7, 6, 5, 4};

  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, true, payload, sig);

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string parse_error;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed, &parse_error));

  cosesign1::validation::VerifyOptions opt;
  opt.public_key_bytes = std::move(der);
  opt.external_payload = payload;

  const auto r = cosesign1::validation::VerifyParsedCoseSign1("SigValidator", parsed, std::nullopt, opt);
  REQUIRE(r.is_valid);
}

TEST_CASE("VerifyParsedCoseSign1 detached payload uses options.external_payload_provider when external not passed") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  auto der = cosesign1::tests::PublicKeyDerFromKey(key.get());

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-7);
  const std::vector<std::uint8_t> payload = {5, 4, 3, 2, 1};

  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, true, payload, sig);

  cosesign1::common::cbor::ParsedCoseSign1 parsed;
  std::string parse_error;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed, &parse_error));

  cosesign1::validation::VerifyOptions opt;
  opt.public_key_bytes = std::move(der);
  opt.external_payload_provider = [payload]() { return payload; };

  const auto r = cosesign1::validation::VerifyParsedCoseSign1("SigValidator", parsed, std::nullopt, opt);
  REQUIRE(r.is_valid);
}
