#include "coverage_hooks.h"

#include <cstdint>
#include <memory>
#include <span>
#include <unordered_map>
#include <vector>

#include "cosesign1/common/cose_sign1.h"

#include "cosesign1/validation/cose_sign1_validation_builder.h"
#include "cosesign1/validation/validator.h"

namespace cosesign1::internal {

namespace {

static volatile std::uint32_t g_dtor_sink = 0;

struct AlwaysOk final : cosesign1::validation::ICoseSign1Validator {
  cosesign1::validation::ValidationResult Validate(const cosesign1::validation::ParsedCoseSign1&,
                                                   const cosesign1::validation::CoseSign1ValidationContext&) const override {
    std::unordered_map<std::string, std::string> md;
    md.emplace("k", "v");
    return cosesign1::validation::ValidationResult::Success("AlwaysOk", std::move(md));
  }
};

struct AlwaysOkLast final : cosesign1::validation::ICoseSign1Validator, cosesign1::validation::ILastCoseSign1Validator {
  cosesign1::validation::ValidationResult Validate(const cosesign1::validation::ParsedCoseSign1&,
                                                   const cosesign1::validation::CoseSign1ValidationContext&) const override {
    std::unordered_map<std::string, std::string> md;
    md.emplace("k2", "v2");
    return cosesign1::validation::ValidationResult::Success("AlwaysOkLast", std::move(md));
  }
};

struct AlwaysFail final : cosesign1::validation::ICoseSign1Validator {
  cosesign1::validation::ValidationResult Validate(const cosesign1::validation::ParsedCoseSign1&,
                                                   const cosesign1::validation::CoseSign1ValidationContext&) const override {
    return cosesign1::validation::ValidationResult::Failure("AlwaysFail", "forced", "forced");
  }
};

} // namespace

void RunCoverageHooks_ValidationHeaders() {
  // Cover marker interface destructor inside the library.
  {
    struct LastOnly final : cosesign1::validation::ILastCoseSign1Validator {
      ~LastOnly() override { ++g_dtor_sink; }
    };

    cosesign1::validation::ILastCoseSign1Validator* p = new LastOnly();
    delete p;
  }

  // Cover template validator destructor inside the library.
  {
    struct V final : cosesign1::validation::IValidator<int> {
      cosesign1::validation::ValidationResult Validate(const int&) const override {
        return cosesign1::validation::ValidationResult::Success("V");
      }
      ~V() override { ++g_dtor_sink; }
    };

    cosesign1::validation::IValidator<int>* v = new V();
    (void)v->Validate(0);
    delete v;
  }

  // Exercise the validation builder types inside the library module.
  cosesign1::validation::ParsedCoseSign1 parsed;
  cosesign1::validation::CoseSign1ValidationContext ctx;

  {
    cosesign1::validation::CoseSign1ValidationBuilder b;
    b.AddValidator(std::make_shared<AlwaysOk>());
    b.AddValidator(std::make_shared<AlwaysOkLast>());
    b.StopOnFirstFailure(false);
    b.RunInParallel(false);
    const auto r = b.Build().Validate(parsed, ctx);
    (void)r;
  }

  {
    cosesign1::validation::CoseSign1ValidationBuilder b;
    b.AddValidator(std::make_shared<AlwaysFail>());
    b.AddValidator(std::make_shared<AlwaysOkLast>());
    b.StopOnFirstFailure(true);
    b.RunInParallel(true);
    const auto r = b.Build().Validate(parsed, ctx);
    (void)r;
  }

  // Exercise CoseSign1SignatureValidator external payload selection logic inside the library.
  {
    cosesign1::validation::VerifyOptions opt;
    opt.expected_alg = cosesign1::validation::CoseAlgorithm::ES256;

    cosesign1::validation::CoseSign1SignatureValidator v("Sig", opt);

    const std::vector<std::uint8_t> payload = {1, 2, 3};
    cosesign1::validation::CoseSign1ValidationContext c;
    c.external_payload = std::span<const std::uint8_t>(payload.data(), payload.size());
    (void)v.Validate(parsed, c);
  }

  {
    cosesign1::validation::VerifyOptions opt;
    opt.expected_alg = cosesign1::validation::CoseAlgorithm::ES256;
    opt.external_payload = std::vector<std::uint8_t>{4, 5};

    cosesign1::validation::CoseSign1SignatureValidator v("Sig", opt);
    cosesign1::validation::CoseSign1ValidationContext c;
    (void)v.Validate(parsed, c);
  }

  {
    cosesign1::validation::VerifyOptions opt;
    opt.expected_alg = cosesign1::validation::CoseAlgorithm::ES256;

    cosesign1::validation::CoseSign1SignatureValidator v("Sig", opt);
    cosesign1::validation::CoseSign1ValidationContext c;
    c.external_payload_provider = []() { return std::vector<std::uint8_t>{6, 7, 8}; };
    (void)v.Validate(parsed, c);
  }

  {
    cosesign1::validation::VerifyOptions opt;
    opt.expected_alg = cosesign1::validation::CoseAlgorithm::ES256;
    opt.external_payload_provider = []() { return std::vector<std::uint8_t>{9}; };

    cosesign1::validation::CoseSign1SignatureValidator v("Sig", opt);
    cosesign1::validation::CoseSign1ValidationContext c;
    (void)v.Validate(parsed, c);
  }
}

} // namespace cosesign1::internal
