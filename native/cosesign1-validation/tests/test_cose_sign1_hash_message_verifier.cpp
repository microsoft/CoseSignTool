// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file test_cose_sign1_hash_message_verifier.cpp
 * @brief Unit tests for CoseSign1HashMessageVerifier.
 */

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>

#include <cosesign1/common/cbor.h>

#include "cosesign1/validation/cose_sign1_hash_message_verifier.h"
#include "cosesign1/validation/cose_sign1_validation_builder.h"
#include "test_utils.h"

namespace {

using ParsedCoseSign1 = cosesign1::validation::ParsedCoseSign1;

bool HasErrorCode(const cosesign1::validation::ValidationResult& r, std::string_view code) {
  for (const auto& f : r.failures) {
    if (f.error_code && *f.error_code == code) {
      return true;
    }
  }
  return false;
}

std::vector<std::uint8_t> ComputeSha256(std::span<const std::uint8_t> data) {
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
  REQUIRE(ctx != nullptr);

  REQUIRE(EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) == 1);
  if (!data.empty()) {
    REQUIRE(EVP_DigestUpdate(ctx.get(), data.data(), data.size()) == 1);
  }

  unsigned int out_len = EVP_MD_size(EVP_sha256());
  std::vector<std::uint8_t> out(static_cast<std::size_t>(out_len));
  REQUIRE(EVP_DigestFinal_ex(ctx.get(), out.data(), &out_len) == 1);
  out.resize(static_cast<std::size_t>(out_len));
  return out;
}

std::vector<std::uint8_t> ComputeSha512(std::span<const std::uint8_t> data) {
  std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
  REQUIRE(ctx != nullptr);

  REQUIRE(EVP_DigestInit_ex(ctx.get(), EVP_sha512(), nullptr) == 1);
  if (!data.empty()) {
    REQUIRE(EVP_DigestUpdate(ctx.get(), data.data(), data.size()) == 1);
  }

  unsigned int out_len = EVP_MD_size(EVP_sha512());
  std::vector<std::uint8_t> out(static_cast<std::size_t>(out_len));
  REQUIRE(EVP_DigestFinal_ex(ctx.get(), out.data(), &out_len) == 1);
  out.resize(static_cast<std::size_t>(out_len));
  return out;
}

std::vector<std::uint8_t> MakeProtectedHeaderAlgAndPayloadHashAlg(std::int64_t sig_alg, std::int64_t payload_hash_alg) {
  // Encoded header map: { 1: sig_alg, 258: payload_hash_alg }
  std::vector<std::uint8_t> buf(64);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);

    CborEncoder map;
    auto err = cbor_encoder_create_map(&enc, &map, 2);
    if (err == CborErrorOutOfMemory) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(err == CborNoError);

    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, sig_alg) == CborNoError);

    REQUIRE(cbor_encode_int(&map, cosesign1::validation::kCoseHashEnvelopePayloadHashAlgLabel) == CborNoError);
    REQUIRE(cbor_encode_int(&map, payload_hash_alg) == CborNoError);

    err = cbor_encoder_close_container(&enc, &map);
    if (err == CborErrorOutOfMemory) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(err == CborNoError);

    const size_t used = cbor_encoder_get_buffer_size(&enc, buf.data());
    buf.resize(used);
    return buf;
  }
}

std::vector<std::uint8_t> MakeCoseSign1WithUnprotectedPayloadHashAlg(const std::vector<std::uint8_t>& protected_header_bstr,
                                                                     std::int64_t unprotected_payload_hash_alg,
                                                                     std::span<const std::uint8_t> payload,
                                                                     std::span<const std::uint8_t> signature,
                                                                     bool payload_is_detached) {
  // COSE_Sign1 = [protected: bstr, unprotected: map, payload: bstr/null, signature: bstr]
  std::vector<std::uint8_t> buf(256 + protected_header_bstr.size() + payload.size() + signature.size());
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);

    CborEncoder arr;
    auto err = cbor_encoder_create_array(&enc, &arr, 4);
    if (err == CborErrorOutOfMemory) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(err == CborNoError);

    REQUIRE(cbor_encode_byte_string(&arr, protected_header_bstr.data(), protected_header_bstr.size()) == CborNoError);

    CborEncoder map;
    err = cbor_encoder_create_map(&arr, &map, 1);
    if (err == CborErrorOutOfMemory) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(err == CborNoError);

    REQUIRE(cbor_encode_int(&map, cosesign1::validation::kCoseHashEnvelopePayloadHashAlgLabel) == CborNoError);
    REQUIRE(cbor_encode_int(&map, unprotected_payload_hash_alg) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&arr, &map) == CborNoError);

    if (payload_is_detached) {
      REQUIRE(cbor_encode_null(&arr) == CborNoError);
    } else {
      REQUIRE(cbor_encode_byte_string(&arr, payload.data(), payload.size()) == CborNoError);
    }

    REQUIRE(cbor_encode_byte_string(&arr, signature.data(), signature.size()) == CborNoError);
    err = cbor_encoder_close_container(&enc, &arr);
    if (err == CborErrorOutOfMemory) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(err == CborNoError);

    const size_t used = cbor_encoder_get_buffer_size(&enc, buf.data());
    buf.resize(used);
    return buf;
  }
}


struct OrderRecorder {
  std::mutex m;
  std::vector<int> order;

  void Push(int id) {
    std::lock_guard<std::mutex> lock(m);
    order.push_back(id);
  }
};

class RecordingValidator final : public cosesign1::validation::ICoseSign1Validator {
 public:
  RecordingValidator(std::shared_ptr<OrderRecorder> rec, int id) : rec_(std::move(rec)), id_(id) {}

  cosesign1::validation::ValidationResult Validate(const ParsedCoseSign1&,
                                                  const cosesign1::validation::CoseSign1ValidationContext&) const override {
    rec_->Push(id_);
    return cosesign1::validation::ValidationResult::Success("RecordingValidator");
  }

 private:
  std::shared_ptr<OrderRecorder> rec_;
  int id_;
};

class RecordingLastValidator final : public cosesign1::validation::ICoseSign1Validator,
                                    public cosesign1::validation::ILastCoseSign1Validator {
 public:
  RecordingLastValidator(std::shared_ptr<OrderRecorder> rec,
                        int id,
                        std::shared_ptr<cosesign1::validation::ICoseSign1Validator> inner)
      : rec_(std::move(rec)), id_(id), inner_(std::move(inner)) {}

  cosesign1::validation::ValidationResult Validate(const ParsedCoseSign1& input,
                                                  const cosesign1::validation::CoseSign1ValidationContext& context) const override {
    rec_->Push(id_);
    return inner_->Validate(input, context);
  }

 private:
  std::shared_ptr<OrderRecorder> rec_;
  int id_;
  std::shared_ptr<cosesign1::validation::ICoseSign1Validator> inner_;
};

} // namespace

TEST_CASE("CoseSign1HashMessageVerifier validates payload hash") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const std::vector<std::uint8_t> external_payload = {9, 8, 7, 6, 5, 4, 3, 2, 1};
  const auto embedded_hash = ComputeSha256(external_payload);

  const auto protected_hdr = MakeProtectedHeaderAlgAndPayloadHashAlg(-7 /* ES256 */, -16 /* SHA-256 */);
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, embedded_hash);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false /* embedded payload */, embedded_hash, sig);

  ParsedCoseSign1 parsed;
  std::string parse_error;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed, &parse_error));

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.AddValidator(std::make_shared<cosesign1::validation::CoseSign1HashMessageVerifier>());

  const auto r = b.Validate(parsed, std::span<const std::uint8_t>(external_payload.data(), external_payload.size()));
  REQUIRE(r.is_valid);
}

TEST_CASE("CoseSign1HashMessageVerifier validates empty external payload") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const std::vector<std::uint8_t> external_payload;
  const auto embedded_hash = ComputeSha256(external_payload);

  const auto protected_hdr = MakeProtectedHeaderAlgAndPayloadHashAlg(-7 /* ES256 */, -16 /* SHA-256 */);
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, embedded_hash);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false /* embedded payload */, embedded_hash, sig);

  ParsedCoseSign1 parsed;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed));

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.AddValidator(std::make_shared<cosesign1::validation::CoseSign1HashMessageVerifier>());

  const auto r = b.Validate(parsed, std::span<const std::uint8_t>(external_payload.data(), external_payload.size()));
  REQUIRE(r.is_valid);
}

TEST_CASE("CoseSign1HashMessageVerifier validates payload hash (SHA-512)") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const std::vector<std::uint8_t> external_payload = {9, 8, 7, 6, 5, 4, 3, 2, 1};
  const auto embedded_hash = ComputeSha512(external_payload);

  const auto protected_hdr = MakeProtectedHeaderAlgAndPayloadHashAlg(-7 /* ES256 */, -44 /* SHA-512 */);
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, embedded_hash);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false /* embedded payload */, embedded_hash, sig);

  ParsedCoseSign1 parsed;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed));

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.AddValidator(std::make_shared<cosesign1::validation::CoseSign1HashMessageVerifier>());

  const auto r = b.Validate(parsed, std::span<const std::uint8_t>(external_payload.data(), external_payload.size()));
  REQUIRE(r.is_valid);
}

TEST_CASE("CoseSign1HashMessageVerifier rejects payload-hash-alg in unprotected headers") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const std::vector<std::uint8_t> external_payload = {1, 2, 3};
  const auto embedded_hash = ComputeSha256(external_payload);

  const auto protected_hdr = MakeProtectedHeaderAlgAndPayloadHashAlg(-7 /* ES256 */, -16 /* SHA-256 */);
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, embedded_hash);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);

  const auto cose = MakeCoseSign1WithUnprotectedPayloadHashAlg(protected_hdr,
                                                               -16 /* SHA-256 */,
                                                               embedded_hash,
                                                               sig,
                                                               false /* payload embedded */);

  ParsedCoseSign1 parsed;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed));

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.AddValidator(std::make_shared<cosesign1::validation::CoseSign1HashMessageVerifier>());

  const auto r = b.Validate(parsed, std::span<const std::uint8_t>(external_payload.data(), external_payload.size()));
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "cosehash.payload_hash_alg_unprotected"));
}

TEST_CASE("CoseSign1HashMessageVerifier rejects missing payload-hash-alg in protected headers") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const std::vector<std::uint8_t> external_payload = {1, 2, 3};
  const auto embedded_hash = ComputeSha256(external_payload);

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-7 /* ES256 */);
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, embedded_hash);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false /* embedded payload */, embedded_hash, sig);

  ParsedCoseSign1 parsed;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed));

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.AddValidator(std::make_shared<cosesign1::validation::CoseSign1HashMessageVerifier>());

  const auto r = b.Validate(parsed, std::span<const std::uint8_t>(external_payload.data(), external_payload.size()));
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "cosehash.payload_hash_alg_missing"));
}

TEST_CASE("CoseSign1HashMessageVerifier rejects unsupported payload-hash-alg") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const std::vector<std::uint8_t> external_payload = {1, 2, 3};
  const auto embedded_hash = ComputeSha256(external_payload);

  const auto protected_hdr = MakeProtectedHeaderAlgAndPayloadHashAlg(-7 /* ES256 */, -999 /* unknown */);
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, embedded_hash);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false /* embedded payload */, embedded_hash, sig);

  ParsedCoseSign1 parsed;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed));

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.AddValidator(std::make_shared<cosesign1::validation::CoseSign1HashMessageVerifier>());

  const auto r = b.Validate(parsed, std::span<const std::uint8_t>(external_payload.data(), external_payload.size()));
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "cosehash.payload_hash_alg_unsupported"));
}

TEST_CASE("CoseSign1HashMessageVerifier rejects missing embedded hash payload") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const std::vector<std::uint8_t> external_payload = {1, 2, 3};
  const auto embedded_hash = ComputeSha256(external_payload);

  const auto protected_hdr = MakeProtectedHeaderAlgAndPayloadHashAlg(-7 /* ES256 */, -16 /* SHA-256 */);
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, embedded_hash);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);

  // Detached payload => payload==null.
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, true /* detached */, embedded_hash, sig);

  ParsedCoseSign1 parsed;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed));

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.AddValidator(std::make_shared<cosesign1::validation::CoseSign1HashMessageVerifier>());

  const auto r = b.Validate(parsed, std::span<const std::uint8_t>(external_payload.data(), external_payload.size()));
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "cosehash.embedded_hash_missing"));
}

TEST_CASE("CoseSign1HashMessageVerifier rejects missing external payload") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const std::vector<std::uint8_t> external_payload = {1, 2, 3};
  const auto embedded_hash = ComputeSha256(external_payload);

  const auto protected_hdr = MakeProtectedHeaderAlgAndPayloadHashAlg(-7 /* ES256 */, -16 /* SHA-256 */);
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, embedded_hash);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false /* embedded payload */, embedded_hash, sig);

  ParsedCoseSign1 parsed;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed));

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.AddValidator(std::make_shared<cosesign1::validation::CoseSign1HashMessageVerifier>());

  const auto r = b.Validate(parsed);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "cosehash.external_payload_missing"));
}

TEST_CASE("CoseSign1HashMessageVerifier rejects payload hash mismatch") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const std::vector<std::uint8_t> external_payload = {1, 2, 3};
  const std::vector<std::uint8_t> different_external_payload = {3, 2, 1};
  const auto embedded_hash = ComputeSha256(external_payload);

  const auto protected_hdr = MakeProtectedHeaderAlgAndPayloadHashAlg(-7 /* ES256 */, -16 /* SHA-256 */);
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, embedded_hash);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false /* embedded payload */, embedded_hash, sig);

  ParsedCoseSign1 parsed;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed));

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.AddValidator(std::make_shared<cosesign1::validation::CoseSign1HashMessageVerifier>());

  const auto r = b.Validate(parsed,
                            std::span<const std::uint8_t>(different_external_payload.data(), different_external_payload.size()));
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "cosehash.payload_hash_mismatch"));
}

TEST_CASE("CoseSign1HashMessageVerifier uses instance payload provider") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const std::vector<std::uint8_t> external_payload = {9, 9, 9};
  const auto embedded_hash = ComputeSha256(external_payload);

  const auto protected_hdr = MakeProtectedHeaderAlgAndPayloadHashAlg(-7 /* ES256 */, -16 /* SHA-256 */);
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, embedded_hash);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false /* embedded payload */, embedded_hash, sig);

  ParsedCoseSign1 parsed;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed));

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.AddValidator(std::make_shared<cosesign1::validation::CoseSign1HashMessageVerifier>([&external_payload]() {
    return external_payload;
  }));

  const auto r = b.Validate(parsed);
  REQUIRE(r.is_valid);
}

TEST_CASE("CoseSign1HashMessageVerifier is always last (sequential)") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const std::vector<std::uint8_t> external_payload = {1, 2, 3, 4};
  const auto embedded_hash = ComputeSha256(external_payload);

  const auto protected_hdr = MakeProtectedHeaderAlgAndPayloadHashAlg(-7 /* ES256 */, -16 /* SHA-256 */);
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, embedded_hash);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false /* embedded payload */, embedded_hash, sig);

  ParsedCoseSign1 parsed;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed));

  auto recorder = std::make_shared<OrderRecorder>();
  auto verifier = std::make_shared<cosesign1::validation::CoseSign1HashMessageVerifier>();

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.RunInParallel(false);
  b.AddValidator(std::make_shared<RecordingLastValidator>(recorder, 2, verifier));
  b.AddValidator(std::make_shared<RecordingValidator>(recorder, 1));

  const auto r = b.Validate(parsed, std::span<const std::uint8_t>(external_payload.data(), external_payload.size()));
  REQUIRE(r.is_valid);

  REQUIRE(recorder->order.size() == 2);
  REQUIRE(recorder->order[0] == 1);
  REQUIRE(recorder->order[1] == 2);
}

TEST_CASE("CoseSign1HashMessageVerifier is always last (parallel)") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const std::vector<std::uint8_t> external_payload = {1, 2, 3, 4};
  const auto embedded_hash = ComputeSha256(external_payload);

  const auto protected_hdr = MakeProtectedHeaderAlgAndPayloadHashAlg(-7 /* ES256 */, -16 /* SHA-256 */);
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, embedded_hash);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false /* embedded payload */, embedded_hash, sig);

  ParsedCoseSign1 parsed;
  REQUIRE(cosesign1::common::cbor::ParseCoseSign1(cose, parsed));

  auto recorder = std::make_shared<OrderRecorder>();
  auto verifier = std::make_shared<cosesign1::validation::CoseSign1HashMessageVerifier>();

  cosesign1::validation::CoseSign1ValidationBuilder b;
  b.RunInParallel(true);
  b.AddValidator(std::make_shared<RecordingLastValidator>(recorder, 2, verifier));
  b.AddValidator(std::make_shared<RecordingValidator>(recorder, 1));

  const auto r = b.Validate(parsed, std::span<const std::uint8_t>(external_payload.data(), external_payload.size()));
  REQUIRE(r.is_valid);

  REQUIRE_FALSE(recorder->order.empty());
  REQUIRE(recorder->order.back() == 2);
}
