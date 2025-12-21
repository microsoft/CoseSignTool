// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file test_verify_more_cases.cpp
 * @brief Additional COSE_Sign1 verification test cases.
 */

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include "cosesign1/validation/cose_sign1_verifier.h"
#include "cosesign1/validation/validator.h"

#include "../src/internal/openssl_utils.h"

#include "test_utils.h"

namespace {

bool HasErrorCode(const cosesign1::validation::ValidationResult& r, std::string_view code) {
  for (const auto& f : r.failures) {
    if (f.error_code && *f.error_code == code) {
      return true;
    }
  }
  return false;
}

using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;

BioPtr MakeBio() {
  return BioPtr(BIO_new(BIO_s_mem()), &BIO_free);
}

std::string BioToString(BIO* bio) {
  char* data = nullptr;
  const long len = BIO_get_mem_data(bio, &data);
  REQUIRE(len > 0);
  REQUIRE(data != nullptr);
  return std::string(data, static_cast<std::size_t>(len));
}

std::string MakeSelfSignedCertPem(EVP_PKEY* key) {
  X509* x = X509_new();
  REQUIRE(x != nullptr);

  REQUIRE(X509_set_version(x, 2) == 1);
  ASN1_INTEGER_set(X509_get_serialNumber(x), 1);

  X509_gmtime_adj(X509_get_notBefore(x), 0);
  X509_gmtime_adj(X509_get_notAfter(x), 60 * 60);

  X509_NAME* name = X509_NAME_new();
  REQUIRE(name != nullptr);
  REQUIRE(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    reinterpret_cast<const unsigned char*>("Test"), -1, -1, 0) == 1);
  REQUIRE(X509_set_subject_name(x, name) == 1);
  REQUIRE(X509_set_issuer_name(x, name) == 1);
  X509_NAME_free(name);

  REQUIRE(X509_set_pubkey(x, key) == 1);
  REQUIRE(X509_sign(x, key, EVP_sha256()) > 0);

  auto bio = MakeBio();
  REQUIRE(bio);
  REQUIRE(PEM_write_bio_X509(bio.get(), x) == 1);

  X509_free(x);
  return BioToString(bio.get());
}

std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> GenerateEcKey(int curve_nid) {
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  REQUIRE(pctx != nullptr);
  REQUIRE(EVP_PKEY_keygen_init(pctx) == 1);
  REQUIRE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, curve_nid) == 1);

  EVP_PKEY* key = nullptr;
  REQUIRE(EVP_PKEY_keygen(pctx, &key) == 1);
  EVP_PKEY_CTX_free(pctx);
  return {key, &EVP_PKEY_free};
}

std::vector<std::uint8_t> SignEcdsaDer(EVP_PKEY* key, const EVP_MD* md, std::span<const std::uint8_t> to_be_signed) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  REQUIRE(ctx != nullptr);
  REQUIRE(EVP_DigestSignInit(ctx, nullptr, md, nullptr, key) == 1);
  REQUIRE(EVP_DigestSignUpdate(ctx, to_be_signed.data(), to_be_signed.size()) == 1);

  size_t sig_len = 0;
  REQUIRE(EVP_DigestSignFinal(ctx, nullptr, &sig_len) == 1);
  std::vector<std::uint8_t> sig(sig_len);
  REQUIRE(EVP_DigestSignFinal(ctx, sig.data(), &sig_len) == 1);
  sig.resize(sig_len);

  EVP_MD_CTX_free(ctx);
  return sig;
}

std::vector<std::uint8_t> SignRs256(EVP_PKEY* key, std::span<const std::uint8_t> to_be_signed) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  REQUIRE(ctx != nullptr);
  REQUIRE(EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1);
  REQUIRE(EVP_DigestSignUpdate(ctx, to_be_signed.data(), to_be_signed.size()) == 1);

  size_t sig_len = 0;
  REQUIRE(EVP_DigestSignFinal(ctx, nullptr, &sig_len) == 1);
  std::vector<std::uint8_t> sig(sig_len);
  REQUIRE(EVP_DigestSignFinal(ctx, sig.data(), &sig_len) == 1);
  sig.resize(sig_len);

  EVP_MD_CTX_free(ctx);
  return sig;
}

std::vector<std::uint8_t> ProtectedHeaderNoAlg() {
  std::vector<std::uint8_t> buf(64);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);

    CborEncoder map;
    const auto err = cbor_encoder_create_map(&enc, &map, 1);
    if (err == CborErrorOutOfMemory) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(err == CborNoError);

    REQUIRE(cbor_encode_int(&map, 999) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);

    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

} // namespace

TEST_CASE("IValidator virtual destructor is coverable") {
  struct V final : public cosesign1::validation::IValidator<int> {
    cosesign1::validation::ValidationResult Validate(const int&) const override {
      return cosesign1::validation::ValidationResult::Success("V");
    }
  };

  std::unique_ptr<cosesign1::validation::IValidator<int>> v = std::make_unique<V>();
  REQUIRE(v->Validate(123).is_valid);
  v.reset();
}

TEST_CASE("VerifyCoseSign1 returns CBOR_PARSE_ERROR on garbage") {
  std::vector<std::uint8_t> not_cbor = {0x01, 0x02, 0x03, 0x04};

  cosesign1::validation::VerifyOptions opt;
  const auto r = cosesign1::validation::VerifyCoseSign1("Sig", not_cbor, opt);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "CBOR_PARSE_ERROR"));
}

TEST_CASE("VerifyCoseSign1 returns MISSING_ALG when no alg header") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  REQUIRE(key);

  const auto protected_hdr = ProtectedHeaderNoAlg();
  const std::vector<std::uint8_t> payload = {1, 2, 3};
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);

  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.public_key_bytes = cosesign1::tests::PublicKeyDerFromKey(key.get());
  const auto r = cosesign1::validation::VerifyCoseSign1("Sig", cose, opt);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "MISSING_ALG"));
}

TEST_CASE("VerifyCoseSign1 returns ALG_MISMATCH when expected differs") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  REQUIRE(key);

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-7);
  const std::vector<std::uint8_t> payload = {1, 2, 3};
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);

  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.public_key_bytes = cosesign1::tests::PublicKeyDerFromKey(key.get());
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::ES384;

  const auto r = cosesign1::validation::VerifyCoseSign1("Sig", cose, opt);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "ALG_MISMATCH"));
}

TEST_CASE("VerifyCoseSign1 returns UNSUPPORTED_ALG") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  REQUIRE(key);

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(12345);
  const std::vector<std::uint8_t> payload = {1, 2, 3};
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);

  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.public_key_bytes = cosesign1::tests::PublicKeyDerFromKey(key.get());

  const auto r = cosesign1::validation::VerifyCoseSign1("Sig", cose, opt);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "UNSUPPORTED_ALG"));
}

TEST_CASE("VerifyCoseSign1 returns MISSING_KEY for classic algorithms") {
  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-7);
  const std::vector<std::uint8_t> payload = {1, 2, 3};
  const std::vector<std::uint8_t> sig = {0x00};
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  const auto r = cosesign1::validation::VerifyCoseSign1("Sig", cose, opt);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "MISSING_KEY"));
}

TEST_CASE("VerifyCoseSign1 returns INVALID_PUBLIC_KEY for invalid public_key_bytes") {
  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-7);
  const std::vector<std::uint8_t> payload = {1, 2, 3};
  const std::vector<std::uint8_t> sig = {0x00};
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.public_key_bytes = std::vector<std::uint8_t>{0x01, 0x02, 0x03, 0x04};

  const auto r = cosesign1::validation::VerifyCoseSign1("Sig", cose, opt);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "INVALID_PUBLIC_KEY"));
}

TEST_CASE("VerifyCoseSign1 RS256 succeeds") {
  auto rsa = cosesign1::tests::GenerateRsaKey(2048);
  REQUIRE(rsa);

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-257); // RS256
  const std::vector<std::uint8_t> payload = {9, 8, 7, 6};
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = SignRs256(rsa.get(), tbs);

  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::RS256;
  opt.public_key_bytes = cosesign1::tests::PublicKeyDerFromKey(rsa.get());

  const auto r = cosesign1::validation::VerifyCoseSign1("Sig", cose, opt);
  REQUIRE(r.is_valid);
}

TEST_CASE("VerifyCoseSign1 ES384 succeeds") {
  auto ec = GenerateEcKey(NID_secp384r1);
  REQUIRE(ec);

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-35); // ES384
  const std::vector<std::uint8_t> payload = {0xAA, 0xBB, 0xCC};
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);

  const auto der = SignEcdsaDer(ec.get(), EVP_sha384(), tbs);
  const auto raw = cosesign1::internal::EcdsaDerToCoseRaw(der, 48);
  REQUIRE(raw);

  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, *raw);

  cosesign1::validation::VerifyOptions opt;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::ES384;
  opt.public_key_bytes = cosesign1::tests::PublicKeyDerFromKey(ec.get());

  const auto r = cosesign1::validation::VerifyCoseSign1("Sig", cose, opt);
  REQUIRE(r.is_valid);
}

TEST_CASE("VerifyCoseSign1 ES512 succeeds") {
  auto ec = GenerateEcKey(NID_secp521r1);
  REQUIRE(ec);

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-36); // ES512
  const std::vector<std::uint8_t> payload = {0x01, 0x02, 0x03};
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);

  const auto der = SignEcdsaDer(ec.get(), EVP_sha512(), tbs);
  const auto raw = cosesign1::internal::EcdsaDerToCoseRaw(der, 66);
  REQUIRE(raw);

  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, *raw);

  cosesign1::validation::VerifyOptions opt;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::ES512;
  opt.public_key_bytes = cosesign1::tests::PublicKeyDerFromKey(ec.get());

  const auto r = cosesign1::validation::VerifyCoseSign1("Sig", cose, opt);
  REQUIRE(r.is_valid);
}

TEST_CASE("LoadPublicKeyOrCertFromPem accepts certificate PEM") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  REQUIRE(key);

  const auto cert_pem = MakeSelfSignedCertPem(key.get());
  auto loaded = cosesign1::internal::LoadPublicKeyOrCertFromPem(cert_pem);
  REQUIRE(loaded);
}

#if defined(COSESIGN1_ENABLE_PQC)
TEST_CASE("VerifyCoseSign1 MLDsa44 returns MISSING_KEY when none provided") {
  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-48);
  const std::vector<std::uint8_t> payload = {1, 2, 3};
  const std::vector<std::uint8_t> sig = {0x00};
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::MLDsa44;

  const auto r = cosesign1::validation::VerifyCoseSign1("Sig", cose, opt);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "MISSING_KEY"));
}

TEST_CASE("VerifyCoseSign1 MLDsa44 accepts public_key_bytes input") {
  // We cannot generate a real PQC signature here, but we can still exercise the
  // VerifyOptions.public_key_bytes plumbing.

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-48);
  const std::vector<std::uint8_t> payload = {1, 2, 3};
  const std::vector<std::uint8_t> sig = {0x01, 0x02, 0x03};
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::MLDsa44;
  opt.public_key_bytes = std::vector<std::uint8_t>(32, 0x01);

  const auto r = cosesign1::validation::VerifyCoseSign1("Sig", cose, opt);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "SIGNATURE_INVALID"));
}

TEST_CASE("VerifyCoseSign1 MLDsa44 returns INVALID_PUBLIC_KEY for DER-like bytes") {
  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-48);
  const std::vector<std::uint8_t> payload = {1, 2, 3};
  const std::vector<std::uint8_t> sig = {0x01, 0x02, 0x03};
  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::MLDsa44;
  // 0x30 is SEQUENCE, so this will be treated as DER and parsed by OpenSSL.
  opt.public_key_bytes = std::vector<std::uint8_t>(16, 0x30);

  const auto r = cosesign1::validation::VerifyCoseSign1("Sig", cose, opt);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(HasErrorCode(r, "INVALID_PUBLIC_KEY"));
}
#endif
