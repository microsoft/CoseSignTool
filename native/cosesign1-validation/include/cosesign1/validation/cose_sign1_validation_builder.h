#pragma once

#include <future>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include <cosesign1/common/cbor.h>

#include "cosesign1/validation/cose_sign1_verifier.h"
#include "cosesign1/validation/validation_result.h"
#include "cosesign1/validation/validator_markers.h"

namespace cosesign1::validation {

using ParsedCoseSign1 = cosesign1::common::cbor::ParsedCoseSign1;

struct CoseSign1ValidationBuilderContext {
  bool stop_on_first_failure = false;
  bool run_in_parallel = false;
};

struct CoseSign1ValidationContext {
  // If the COSE_Sign1 payload is detached (payload is null), provide the external payload bytes here.
  std::optional<std::span<const std::uint8_t>> external_payload;

  // Optional payload provider for stream-backed payloads.
  // The provider may be invoked by multiple validators; it should return the full payload bytes.
  VerifyOptions::BytesProvider external_payload_provider;
};

class ICoseSign1Validator {
 public:
  virtual ~ICoseSign1Validator() = default;

  virtual ValidationResult Validate(const ParsedCoseSign1& input, const CoseSign1ValidationContext& context) const = 0;
};

class CompositeCoseSign1Validator final {
 public:
  explicit CompositeCoseSign1Validator(std::vector<std::shared_ptr<ICoseSign1Validator>> validators,
                                      CoseSign1ValidationBuilderContext context)
      : validators_(std::move(validators)), context_(context) {}

  ValidationResult Validate(const ParsedCoseSign1& input, const CoseSign1ValidationContext& context) const {
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

 private:
  std::vector<std::shared_ptr<ICoseSign1Validator>> validators_;
  CoseSign1ValidationBuilderContext context_;
};

class CoseSign1ValidationBuilder final {
 public:
  CoseSign1ValidationBuilder& AddValidator(std::shared_ptr<ICoseSign1Validator> validator) {
    if (!validator) {
      throw std::invalid_argument("validator");
    }
    validators_.push_back(std::move(validator));
    return *this;
  }

  CoseSign1ValidationBuilder& StopOnFirstFailure(bool enabled = true) {
    context_.stop_on_first_failure = enabled;
    return *this;
  }

  CoseSign1ValidationBuilder& RunInParallel(bool enabled = true) {
    context_.run_in_parallel = enabled;
    return *this;
  }

  CompositeCoseSign1Validator Build() const { return CompositeCoseSign1Validator(validators_, context_); }

  // Runs all registered validators against a pre-parsed COSE_Sign1.
  ValidationResult Validate(const ParsedCoseSign1& parsed,
                            std::optional<std::span<const std::uint8_t>> external_payload = std::nullopt,
                            VerifyOptions::BytesProvider external_payload_provider = {}) const {
    CoseSign1ValidationContext ctx;
    ctx.external_payload = external_payload;
    ctx.external_payload_provider = std::move(external_payload_provider);
    return Build().Validate(parsed, ctx);
  }

 private:
  std::vector<std::shared_ptr<ICoseSign1Validator>> validators_;
  CoseSign1ValidationBuilderContext context_;
};

// Adapter validator for the built-in signature verifier.
class CoseSign1SignatureValidator final : public ICoseSign1Validator {
 public:
  CoseSign1SignatureValidator(std::string validator_name, VerifyOptions options)
      : validator_name_(std::move(validator_name)), options_(std::move(options)) {}

  ValidationResult Validate(const ParsedCoseSign1& input, const CoseSign1ValidationContext& context) const override {
    std::optional<std::span<const std::uint8_t>> ext = context.external_payload;
    if (!ext && options_.external_payload) {
      ext = std::span<const std::uint8_t>(options_.external_payload->data(), options_.external_payload->size());
    }

    if (!ext && context.external_payload_provider) {
      // Materialize bytes for signature verification.
      owned_external_payload_ = context.external_payload_provider();
      ext = std::span<const std::uint8_t>(owned_external_payload_.data(), owned_external_payload_.size());
    }

    if (!ext && options_.external_payload_provider) {
      owned_external_payload_ = options_.external_payload_provider();
      ext = std::span<const std::uint8_t>(owned_external_payload_.data(), owned_external_payload_.size());
    }
    return VerifyParsedCoseSign1(validator_name_, input, ext, options_);
  }

 private:
  std::string validator_name_;
  VerifyOptions options_;

  // Mutable cache for provider materialization.
  // This is safe because Validate is logically const but may need to own bytes.
  mutable std::vector<std::uint8_t> owned_external_payload_;
};

} // namespace cosesign1::validation
