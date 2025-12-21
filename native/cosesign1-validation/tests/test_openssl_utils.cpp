// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file test_openssl_utils.cpp
 * @brief Unit tests for internal OpenSSL helpers.
 */

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "../src/internal/openssl_utils.h"

#include "test_utils.h"

namespace {

std::vector<std::uint8_t> MakeDerEcdsaSigP256() {
  // Generate a P-256 key and sign arbitrary bytes to produce an ECDSA DER signature.
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  REQUIRE(pctx != nullptr);
  REQUIRE(EVP_PKEY_keygen_init(pctx) == 1);
  REQUIRE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) == 1);

  EVP_PKEY* key = nullptr;
  REQUIRE(EVP_PKEY_keygen(pctx, &key) == 1);
  EVP_PKEY_CTX_free(pctx);

  const std::uint8_t msg[] = {1, 2, 3, 4, 5};
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  REQUIRE(ctx != nullptr);
  REQUIRE(EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1);
  REQUIRE(EVP_DigestSignUpdate(ctx, msg, sizeof(msg)) == 1);

  size_t sig_len = 0;
  REQUIRE(EVP_DigestSignFinal(ctx, nullptr, &sig_len) == 1);
  std::vector<std::uint8_t> sig(sig_len);
  REQUIRE(EVP_DigestSignFinal(ctx, sig.data(), &sig_len) == 1);
  sig.resize(sig_len);

  EVP_MD_CTX_free(ctx);
  EVP_PKEY_free(key);
  return sig;
}

} // namespace

TEST_CASE("CoseEcdsaRawToDer rejects empty and odd-length signatures") {
  REQUIRE_FALSE(cosesign1::internal::CoseEcdsaRawToDer({}).has_value());

  const std::uint8_t odd[] = {0x01, 0x02, 0x03};
  REQUIRE_FALSE(cosesign1::internal::CoseEcdsaRawToDer(odd).has_value());
}

TEST_CASE("EcdsaDerToCoseRaw rejects invalid DER") {
  const std::uint8_t not_der[] = {0x30, 0x01, 0x00};
  REQUIRE_FALSE(cosesign1::internal::EcdsaDerToCoseRaw(not_der, 32).has_value());
}

TEST_CASE("EcdsaDerToCoseRaw rejects too-small component size") {
  const auto der = MakeDerEcdsaSigP256();

  // P-256 needs 32-byte r/s; 1-byte should fail BN_bn2binpad.
  REQUIRE_FALSE(cosesign1::internal::EcdsaDerToCoseRaw(der, 1).has_value());
}

TEST_CASE("ExtractSubjectPublicKeyBytesFromCertificatePem rejects non-certificate") {
  const std::string not_a_cert = "-----BEGIN CERTIFICATE-----\nZm9v\n-----END CERTIFICATE-----\n";
  REQUIRE_FALSE(cosesign1::internal::ExtractSubjectPublicKeyBytesFromCertificatePem(not_a_cert).has_value());
}

TEST_CASE("LoadPublicKeyOrCertFromDer rejects empty") {
  const std::vector<std::uint8_t> empty;
  const auto key = cosesign1::internal::LoadPublicKeyOrCertFromDer(empty);
  REQUIRE_FALSE(static_cast<bool>(key));
}

TEST_CASE("LoadPublicKeyOrCertFromPem loads public key PEM") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  REQUIRE(key);

  const auto pem = cosesign1::tests::PublicKeyPemFromKey(key.get());
  const auto loaded = cosesign1::internal::LoadPublicKeyOrCertFromPem(pem);
  REQUIRE(static_cast<bool>(loaded));
}

TEST_CASE("LoadPublicKeyOrCertFromDer loads SPKI public key DER") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  REQUIRE(key);

  const auto der = cosesign1::tests::PublicKeyDerFromKey(key.get());
  const auto loaded = cosesign1::internal::LoadPublicKeyOrCertFromDer(der);
  REQUIRE(static_cast<bool>(loaded));
}

TEST_CASE("LoadPublicKeyOrCertFromDer rejects SPKI DER with trailing bytes") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  REQUIRE(key);

  auto der = cosesign1::tests::PublicKeyDerFromKey(key.get());
  der.push_back(0x00); // extra byte should prevent full-buffer consumption
  const auto loaded = cosesign1::internal::LoadPublicKeyOrCertFromDer(der);
  REQUIRE_FALSE(static_cast<bool>(loaded));
}

TEST_CASE("LoadPublicKeyOrCertFromDer loads X509 certificate DER") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  REQUIRE(key);

  X509* x = X509_new();
  REQUIRE(x != nullptr);
  REQUIRE(X509_set_version(x, 2) == 1);
  ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
  X509_gmtime_adj(X509_get_notBefore(x), 0);
  X509_gmtime_adj(X509_get_notAfter(x), 60);

  X509_NAME* name = X509_NAME_new();
  REQUIRE(name != nullptr);
  REQUIRE(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    reinterpret_cast<const unsigned char*>("Test"), -1, -1, 0) == 1);
  REQUIRE(X509_set_subject_name(x, name) == 1);
  REQUIRE(X509_set_issuer_name(x, name) == 1);
  X509_NAME_free(name);

  REQUIRE(X509_set_pubkey(x, key.get()) == 1);
  REQUIRE(X509_sign(x, key.get(), EVP_sha256()) > 0);

  int len = i2d_X509(x, nullptr);
  REQUIRE(len > 0);
  std::vector<std::uint8_t> cert_der(static_cast<std::size_t>(len));
  unsigned char* p = cert_der.data();
  REQUIRE(i2d_X509(x, &p) == len);
  X509_free(x);

  const auto loaded = cosesign1::internal::LoadPublicKeyOrCertFromDer(cert_der);
  REQUIRE(static_cast<bool>(loaded));
}

TEST_CASE("LoadPublicKeyOrCertFromDer rejects X509 DER with trailing bytes") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  REQUIRE(key);

  X509* x = X509_new();
  REQUIRE(x != nullptr);
  REQUIRE(X509_set_version(x, 2) == 1);
  ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
  X509_gmtime_adj(X509_get_notBefore(x), 0);
  X509_gmtime_adj(X509_get_notAfter(x), 60);

  X509_NAME* name = X509_NAME_new();
  REQUIRE(name != nullptr);
  REQUIRE(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    reinterpret_cast<const unsigned char*>("Test"), -1, -1, 0) == 1);
  REQUIRE(X509_set_subject_name(x, name) == 1);
  REQUIRE(X509_set_issuer_name(x, name) == 1);
  X509_NAME_free(name);

  REQUIRE(X509_set_pubkey(x, key.get()) == 1);
  REQUIRE(X509_sign(x, key.get(), EVP_sha256()) > 0);

  int len = i2d_X509(x, nullptr);
  REQUIRE(len > 0);
  std::vector<std::uint8_t> cert_der(static_cast<std::size_t>(len));
  unsigned char* p = cert_der.data();
  REQUIRE(i2d_X509(x, &p) == len);
  X509_free(x);

  cert_der.push_back(0x00);
  const auto loaded = cosesign1::internal::LoadPublicKeyOrCertFromDer(cert_der);
  REQUIRE_FALSE(static_cast<bool>(loaded));
}

TEST_CASE("ExtractSubjectPublicKeyBytesFromCertificatePem succeeds on valid cert") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  REQUIRE(key);

  X509* x = X509_new();
  REQUIRE(x != nullptr);
  REQUIRE(X509_set_version(x, 2) == 1);
  ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
  X509_gmtime_adj(X509_get_notBefore(x), 0);
  X509_gmtime_adj(X509_get_notAfter(x), 60);

  X509_NAME* name = X509_NAME_new();
  REQUIRE(name != nullptr);
  REQUIRE(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    reinterpret_cast<const unsigned char*>("Test"), -1, -1, 0) == 1);
  REQUIRE(X509_set_subject_name(x, name) == 1);
  REQUIRE(X509_set_issuer_name(x, name) == 1);
  X509_NAME_free(name);

  REQUIRE(X509_set_pubkey(x, key.get()) == 1);
  REQUIRE(X509_sign(x, key.get(), EVP_sha256()) > 0);

  BIO* bio = BIO_new(BIO_s_mem());
  REQUIRE(bio != nullptr);
  REQUIRE(PEM_write_bio_X509(bio, x) == 1);
  BUF_MEM* mem = nullptr;
  BIO_get_mem_ptr(bio, &mem);
  REQUIRE(mem != nullptr);
  std::string pem(mem->data, static_cast<std::size_t>(mem->length));
  BIO_free(bio);
  X509_free(x);

  const auto spk = cosesign1::internal::ExtractSubjectPublicKeyBytesFromCertificatePem(pem);
  REQUIRE(spk.has_value());
  REQUIRE_FALSE(spk->empty());
}

TEST_CASE("VerifyEs256 returns false for invalid COSE raw signature") {
  auto key = cosesign1::tests::GenerateEcP256Key();
  REQUIRE(key);

  const std::vector<std::uint8_t> tbs = {1, 2, 3, 4};
  const std::vector<std::uint8_t> bad_sig; // empty => invalid
  REQUIRE_FALSE(cosesign1::internal::VerifyEs256(key.get(), tbs, bad_sig));
}

TEST_CASE("VerifyRawSignature returns false on null key") {
  const std::vector<std::uint8_t> msg = {1, 2, 3, 4};
  const std::vector<std::uint8_t> sig = {0x00};
  REQUIRE_FALSE(cosesign1::internal::VerifyRawSignature(nullptr, msg, sig));
}

TEST_CASE("VerifyRawSignature returns false for invalid RSA signature") {
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  REQUIRE(pctx != nullptr);
  REQUIRE(EVP_PKEY_keygen_init(pctx) == 1);
  REQUIRE(EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) == 1);

  EVP_PKEY* key = nullptr;
  REQUIRE(EVP_PKEY_keygen(pctx, &key) == 1);
  EVP_PKEY_CTX_free(pctx);
  REQUIRE(key != nullptr);

  const std::vector<std::uint8_t> msg = {1, 2, 3, 4, 5};
  // 2048-bit RSA signatures are 256 bytes.
  const std::vector<std::uint8_t> bad_sig(256, 0x00);
  REQUIRE_FALSE(cosesign1::internal::VerifyRawSignature(key, msg, bad_sig));

  EVP_PKEY_free(key);
}
