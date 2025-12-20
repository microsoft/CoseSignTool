#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <stdexcept>
#include <vector>

#include <cosesign1/common/cbor.h>

#include "cosesign1/validation/cose_sign1_validation_builder.h"
#include "test_utils.h"

namespace {

struct ParsedFixture {
  cosesign1::validation::ParsedCoseSign1 parsed;
  std::vector<std::uint8_t> payload;
  std::vector<std::uint8_t> public_key_bytes;
};

ParsedFixture MakeEs256Parsed(bool detached_payload) {
  auto key = cosesign1::tests::GenerateEcP256Key();
  auto der = cosesign1::tests::PublicKeyDerFromKey(key.get());

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-7);
  const std::vector<std::uint8_t> payload = {1, 2, 3, 4, 5};

  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, detached_payload, payload, sig);

  cosesign1::validation::ParsedCoseSign1 parsed;
  std::string parse_error;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed, &parse_error));

  ParsedFixture f;
  f.parsed = std::move(parsed);
  f.payload = payload;
  f.public_key_bytes = std::move(der);
  return f;
}

class CountingValidator final : public cosesign1::validation::ICoseSign1Validator {
 public:
  explicit CountingValidator(std::atomic<int>& calls) : calls_(calls) {}

  cosesign1::validation::ValidationResult Validate(const cosesign1::validation::ParsedCoseSign1&,
                                                   const cosesign1::validation::CoseSign1ValidationContext&) const override {
    ++calls_;
    return cosesign1::validation::ValidationResult::Success("CountingValidator");
  }

 private:
  std::atomic<int>& calls_;
};

class FixedResultValidator final : public cosesign1::validation::ICoseSign1Validator {
 public:
  FixedResultValidator(std::atomic<int>& calls, cosesign1::validation::ValidationResult result)
      : calls_(calls), result_(std::move(result)) {}

  cosesign1::validation::ValidationResult Validate(const cosesign1::validation::ParsedCoseSign1&, 
                                                   const cosesign1::validation::CoseSign1ValidationContext&) const override {
    ++calls_;
    return result_;
  }

 private:
  std::atomic<int>& calls_;
  cosesign1::validation::ValidationResult result_;
};

  class LastFixedResultValidator final : public cosesign1::validation::ICoseSign1Validator,
                                         public cosesign1::validation::ILastCoseSign1Validator {
   public:
    LastFixedResultValidator(std::atomic<int>& calls, cosesign1::validation::ValidationResult result)
        : calls_(calls), result_(std::move(result)) {}

    cosesign1::validation::ValidationResult Validate(const cosesign1::validation::ParsedCoseSign1&,
                                                     const cosesign1::validation::CoseSign1ValidationContext&) const override {
      ++calls_;
      return result_;
    }

   private:
    std::atomic<int>& calls_;
    cosesign1::validation::ValidationResult result_;
  };

} // namespace

TEST_CASE("CompositeCoseSign1Validator returns success when empty") {
  const auto f = MakeEs256Parsed(false);
  cosesign1::validation::CoseSign1ValidationBuilder b;
  const auto r = b.Build().Validate(f.parsed, cosesign1::validation::CoseSign1ValidationContext{});
  REQUIRE(r.is_valid);
}

TEST_CASE("CoseSign1ValidationBuilder AddValidator throws on null") {
  cosesign1::validation::CoseSign1ValidationBuilder b;
  REQUIRE_THROWS_AS(b.AddValidator(nullptr), std::invalid_argument);
}

TEST_CASE("CompositeCoseSign1Validator StopOnFirstFailure stops") {
  const auto f = MakeEs256Parsed(false);
  std::atomic<int> a_calls{0};
  std::atomic<int> b_calls{0};

  cosesign1::validation::ValidationFailure failure;
  failure.error_code = "FAIL";
  failure.message = "nope";

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.StopOnFirstFailure(true);
  b.AddValidator(std::make_shared<FixedResultValidator>(a_calls,
      cosesign1::validation::ValidationResult::Failure("A", std::vector<cosesign1::validation::ValidationFailure>{failure})));
  b.AddValidator(std::make_shared<FixedResultValidator>(b_calls, cosesign1::validation::ValidationResult::Success("B")));

  const auto r = b.Build().Validate(f.parsed, cosesign1::validation::CoseSign1ValidationContext{});
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(a_calls.load() == 1);
  REQUIRE(b_calls.load() == 0);
}

TEST_CASE("CompositeCoseSign1Validator RunInParallel aggregates failures") {
  const auto f = MakeEs256Parsed(false);
  std::atomic<int> a_calls{0};
  std::atomic<int> b_calls{0};

  cosesign1::validation::ValidationFailure failure;
  failure.error_code = "FAIL";
  failure.message = "nope";

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.RunInParallel(true);
  b.AddValidator(std::make_shared<FixedResultValidator>(a_calls,
      cosesign1::validation::ValidationResult::Failure("A", std::vector<cosesign1::validation::ValidationFailure>{failure})));
  b.AddValidator(std::make_shared<FixedResultValidator>(b_calls,
      cosesign1::validation::ValidationResult::Failure("B", std::vector<cosesign1::validation::ValidationFailure>{failure})));

  const auto r = b.Build().Validate(f.parsed, cosesign1::validation::CoseSign1ValidationContext{});
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(a_calls.load() == 1);
  REQUIRE(b_calls.load() == 1);
  REQUIRE(r.failures.size() >= 1);
}

TEST_CASE("CompositeCoseSign1Validator merges metadata on success") {
  const auto f = MakeEs256Parsed(false);
  std::atomic<int> a_calls{0};
  std::atomic<int> b_calls{0};

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.RunInParallel(true);
  b.AddValidator(std::make_shared<FixedResultValidator>(a_calls,
      cosesign1::validation::ValidationResult::Success("A", {{"k", "v"}})));
  b.AddValidator(std::make_shared<FixedResultValidator>(b_calls,
      cosesign1::validation::ValidationResult::Success("B", {{"x", "y"}})));

  const auto r = b.Build().Validate(f.parsed, cosesign1::validation::CoseSign1ValidationContext{});
  REQUIRE(r.is_valid);
  REQUIRE(a_calls.load() == 1);
  REQUIRE(b_calls.load() == 1);
  REQUIRE(r.metadata.at("A.k") == "v");
  REQUIRE(r.metadata.at("B.x") == "y");
}

TEST_CASE("CoseSign1ValidationBuilder Validate runs signature validator") {
  const auto f = MakeEs256Parsed(true);

  cosesign1::validation::VerifyOptions opt;
  opt.public_key_bytes = f.public_key_bytes;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::ES256;
  opt.external_payload = f.payload;

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.AddValidator(std::make_shared<cosesign1::validation::CoseSign1SignatureValidator>("Sig", opt));

  const auto r = b.Validate(f.parsed);
  REQUIRE(r.is_valid);
}

TEST_CASE("CoseSign1SignatureValidator prefers context external payload") {
  const auto f = MakeEs256Parsed(true);

  cosesign1::validation::VerifyOptions opt;
  opt.public_key_bytes = f.public_key_bytes;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::ES256;
  opt.external_payload = std::vector<std::uint8_t>{0, 0, 0};

  cosesign1::validation::CoseSign1ValidationContext ctx;
  ctx.external_payload = std::span<const std::uint8_t>(f.payload.data(), f.payload.size());

  cosesign1::validation::CoseSign1SignatureValidator v("Sig", opt);
  const auto r = v.Validate(f.parsed, ctx);
  REQUIRE(r.is_valid);
}

TEST_CASE("CoseSign1SignatureValidator uses context external payload provider") {
  const auto f = MakeEs256Parsed(true);

  cosesign1::validation::VerifyOptions opt;
  opt.public_key_bytes = f.public_key_bytes;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::ES256;

  cosesign1::validation::CoseSign1ValidationContext ctx;
  ctx.external_payload_provider = [payload = f.payload]() { return payload; };

  cosesign1::validation::CoseSign1SignatureValidator v("Sig", opt);
  const auto r = v.Validate(f.parsed, ctx);
  REQUIRE(r.is_valid);
}

TEST_CASE("CoseSign1SignatureValidator uses options external payload provider") {
  const auto f = MakeEs256Parsed(true);

  cosesign1::validation::VerifyOptions opt;
  opt.public_key_bytes = f.public_key_bytes;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::ES256;
  opt.external_payload_provider = [payload = f.payload]() { return payload; };

  cosesign1::validation::CoseSign1ValidationContext ctx;

  cosesign1::validation::CoseSign1SignatureValidator v("Sig", opt);
  const auto r = v.Validate(f.parsed, ctx);
  REQUIRE(r.is_valid);
}

TEST_CASE("CompositeCoseSign1Validator stop-on-first-failure applies to last validators") {
  const auto f = MakeEs256Parsed(false);

  std::atomic<int> last1_calls{0};
  std::atomic<int> last2_calls{0};

  cosesign1::validation::ValidationFailure failure;
  failure.error_code = "FAIL";
  failure.message = "nope";

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.StopOnFirstFailure(true);

  b.AddValidator(std::make_shared<LastFixedResultValidator>(last1_calls,
      cosesign1::validation::ValidationResult::Failure("L1", std::vector<cosesign1::validation::ValidationFailure>{failure})));
  b.AddValidator(std::make_shared<LastFixedResultValidator>(last2_calls,
      cosesign1::validation::ValidationResult::Success("L2")));

  const auto r = b.Build().Validate(f.parsed, cosesign1::validation::CoseSign1ValidationContext{});
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(last1_calls.load() == 1);
  REQUIRE(last2_calls.load() == 0);
}
