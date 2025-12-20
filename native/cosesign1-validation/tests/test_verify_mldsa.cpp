#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <vector>

#include "cosesign1/validation/cose_sign1_verifier.h"
#include "test_utils.h"

#if defined(COSESIGN1_ENABLE_PQC)

TEST_CASE("VerifyCoseSign1 ML-DSA-44 succeeds") {
  constexpr std::int64_t alg = -48; // ML-DSA-44

  const auto kp = cosesign1::tests::GenerateMlDsaKeyPair(alg);

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(alg);
  const std::vector<std::uint8_t> payload = {9, 8, 7, 6, 5, 4, 3, 2, 1};

  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = cosesign1::tests::SignMlDsa(alg, tbs, kp.secret_key);
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.public_key_bytes = kp.public_key;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::MLDsa44;

  auto r = cosesign1::validation::VerifyCoseSign1("SigValidator", cose, opt);
  REQUIRE(r.is_valid);
  REQUIRE(r.validator_name == "SigValidator");
}

#endif
