// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file test_x5c_verify_es256.cpp
 * @brief Unit tests for x5c-based COSE_Sign1 verification.
 */

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <vector>

#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <tinycbor/cbor.h>

#include "cosesign1/validation/cose_sign1_verifier.h"
#include "cosesign1/x509/x5c_verifier.h"

#include "../../cosesign1-validation/tests/test_utils.h"

namespace {

std::vector<std::uint8_t> EncodeProtectedAlgAndX5c(const std::vector<std::uint8_t>& leaf_der) {
  // protected header is a bstr of CBOR map. Include alg=-7 and x5c=[leaf_der]
  std::vector<std::uint8_t> buf(4096 + leaf_der.size());
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);

    CborEncoder map;
    const auto err = cbor_encoder_create_map(&enc, &map, 2);
    if (err == CborErrorOutOfMemory) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(err == CborNoError);

    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, -7) == CborNoError);

    REQUIRE(cbor_encode_int(&map, 33) == CborNoError);
    CborEncoder arr;
    REQUIRE(cbor_encoder_create_array(&map, &arr, 1) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, leaf_der.data(), leaf_der.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &arr) == CborNoError);

    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeProtectedAlgAndX5cRawFallbackShape(const std::vector<std::uint8_t>& leaf_der) {
  // protected header is a bstr of CBOR map.
  // Include alg=-7 and x5c=[leaf_der, 1]. The non-bstr second element causes the
  // common header-map decoder to treat x5c as unknown (monostate), while preserving
  // raw CBOR bytes so the x5c verifier can fall back to parsing the raw value.
  std::vector<std::uint8_t> buf(4096 + leaf_der.size());
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);

    CborEncoder map;
    const auto err = cbor_encoder_create_map(&enc, &map, 2);
    if (err == CborErrorOutOfMemory) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(err == CborNoError);

    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, -7) == CborNoError);

    REQUIRE(cbor_encode_int(&map, 33) == CborNoError);
    CborEncoder arr;
    REQUIRE(cbor_encoder_create_array(&map, &arr, 2) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, leaf_der.data(), leaf_der.size()) == CborNoError);
    REQUIRE(cbor_encode_int(&arr, 1) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &arr) == CborNoError);

    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> MakeCoseSign1WithUnprotectedX5cIndefinite(
    const std::vector<std::uint8_t>& protected_hdr,
    const std::vector<std::uint8_t>& leaf_der,
    const std::vector<std::uint8_t>& payload,
    const std::vector<std::uint8_t>& signature,
    bool detached_payload) {
  // COSE_Sign1 = [protected: bstr, unprotected: map, payload: bstr/null, signature: bstr]
  std::vector<std::uint8_t> buf(4096 + leaf_der.size() + payload.size() + signature.size());
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);

    CborEncoder arr;
    CborError err = cbor_encoder_create_array(&enc, &arr, 4);
    if (err == CborErrorOutOfMemory) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(err == CborNoError);

    REQUIRE(cbor_encode_byte_string(&arr, protected_hdr.data(), protected_hdr.size()) == CborNoError);

    // unprotected map: {33: [leaf_der, 1]} to force raw-value fallback in the verifier.
    CborEncoder map;
    REQUIRE(cbor_encoder_create_map(&arr, &map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 33) == CborNoError);
    CborEncoder x5c;
    REQUIRE(cbor_encoder_create_array(&map, &x5c, 2) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&x5c, leaf_der.data(), leaf_der.size()) == CborNoError);
    REQUIRE(cbor_encode_int(&x5c, 1) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &x5c) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&arr, &map) == CborNoError);

    if (detached_payload) {
      REQUIRE(cbor_encode_null(&arr) == CborNoError);
    } else {
      REQUIRE(cbor_encode_byte_string(&arr, payload.data(), payload.size()) == CborNoError);
    }

    REQUIRE(cbor_encode_byte_string(&arr, signature.data(), signature.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &arr) == CborNoError);

    const size_t used = cbor_encoder_get_buffer_size(&enc, buf.data());
    buf.resize(used);
    return buf;
  }
}

std::vector<std::uint8_t> EncodeUnprotectedWithX5c(const std::vector<std::uint8_t>& leaf_der) {
  std::vector<std::uint8_t> buf(2048 + leaf_der.size());
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);

    CborEncoder map;
    CborError err = cbor_encoder_create_map(&enc, &map, 1);
    if (err == CborErrorOutOfMemory) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(err == CborNoError);

    REQUIRE(cbor_encode_int(&map, 33) == CborNoError);

    CborEncoder arr;
    REQUIRE(cbor_encoder_create_array(&map, &arr, 1) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, leaf_der.data(), leaf_der.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &arr) == CborNoError);

    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);

    const size_t used = cbor_encoder_get_buffer_size(&enc, buf.data());
    buf.resize(used);
    return buf;
  }
}

std::vector<std::uint8_t> MakeSelfSignedCertDer(EVP_PKEY* key) {
  X509* x = X509_new();
  REQUIRE(x != nullptr);

  // Version 3 (0-based)
  REQUIRE(X509_set_version(x, 2) == 1);
  ASN1_INTEGER_set(X509_get_serialNumber(x), 1);

  // Validity
  X509_gmtime_adj(X509_get_notBefore(x), 0);
  X509_gmtime_adj(X509_get_notAfter(x), 60 * 60 * 24);

  // Subject/Issuer
  X509_NAME* name = X509_NAME_new();
  REQUIRE(name != nullptr);
  REQUIRE(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                    reinterpret_cast<const unsigned char*>("Test"), -1, -1, 0) == 1);
  REQUIRE(X509_set_subject_name(x, name) == 1);
  REQUIRE(X509_set_issuer_name(x, name) == 1);
  X509_NAME_free(name);

  REQUIRE(X509_set_pubkey(x, key) == 1);

  REQUIRE(X509_sign(x, key, EVP_sha256()) > 0);

  int len = i2d_X509(x, nullptr);
  REQUIRE(len > 0);
  std::vector<std::uint8_t> der(static_cast<size_t>(len));
  unsigned char* p = der.data();
  REQUIRE(i2d_X509(x, &p) == len);

  X509_free(x);
  return der;
}

std::vector<std::uint8_t> MakeCoseSign1WithX5c(
    const std::vector<std::uint8_t>& protected_hdr,
    const std::vector<std::uint8_t>& unprotected_map_cbor,
    const std::vector<std::uint8_t>& payload,
    const std::vector<std::uint8_t>& signature,
    bool detached_payload) {
  // COSE_Sign1 = [protected: bstr, unprotected: map, payload: bstr/null, signature: bstr]
  std::vector<std::uint8_t> buf(4096 + unprotected_map_cbor.size() + payload.size() + signature.size());
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);

    CborEncoder arr;
    CborError err = cbor_encoder_create_array(&enc, &arr, 4);
    if (err == CborErrorOutOfMemory) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(err == CborNoError);

    REQUIRE(cbor_encode_byte_string(&arr, protected_hdr.data(), protected_hdr.size()) == CborNoError);

    // Copy raw-encoded unprotected map by parsing then re-encoding isn't needed: just encode map directly here.
    // We already have it encoded, but tinycbor doesn't provide a stable "append raw" API, so encode it again.
    // Decode unprotected_map_cbor and re-encode as a map.
    CborParser p;
    CborValue it;
    REQUIRE(cbor_parser_init(unprotected_map_cbor.data(), unprotected_map_cbor.size(), 0, &p, &it) == CborNoError);
    REQUIRE(cbor_value_is_map(&it));

    // For this test, the map is exactly {33:[bstr]}.
    CborEncoder map;
    REQUIRE(cbor_encoder_create_map(&arr, &map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 33) == CborNoError);

    // Extract leaf bytes from encoded map
    CborValue mit;
    REQUIRE(cbor_value_enter_container(&it, &mit) == CborNoError);
    std::int64_t key_int = 0;
    REQUIRE(cbor_value_get_int64(&mit, &key_int) == CborNoError);
    REQUIRE(key_int == 33);
    REQUIRE(cbor_value_advance_fixed(&mit) == CborNoError);
    REQUIRE(cbor_value_is_array(&mit));

    CborValue ait;
    REQUIRE(cbor_value_enter_container(&mit, &ait) == CborNoError);
    size_t leaf_len = 0;
    REQUIRE(cbor_value_calculate_string_length(&ait, &leaf_len) == CborNoError);
    std::vector<std::uint8_t> leaf(leaf_len);
    size_t copied = leaf_len;
    REQUIRE(cbor_value_copy_byte_string(&ait, leaf.data(), &copied, &ait) == CborNoError);
    leaf.resize(copied);

    CborEncoder aenc;
    REQUIRE(cbor_encoder_create_array(&map, &aenc, 1) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&aenc, leaf.data(), leaf.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &aenc) == CborNoError);

    REQUIRE(cbor_encoder_close_container(&arr, &map) == CborNoError);

    if (detached_payload) {
      REQUIRE(cbor_encode_null(&arr) == CborNoError);
    } else {
      REQUIRE(cbor_encode_byte_string(&arr, payload.data(), payload.size()) == CborNoError);
    }

    REQUIRE(cbor_encode_byte_string(&arr, signature.data(), signature.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &arr) == CborNoError);

    const size_t used = cbor_encoder_get_buffer_size(&enc, buf.data());
    buf.resize(used);
    return buf;
  }
}

} // namespace

TEST_CASE("VerifyCoseSign1WithX5c ES256 succeeds") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-7);
  const std::vector<std::uint8_t> payload = {1, 2, 3, 4, 5};

  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);

  const auto leaf_der = MakeSelfSignedCertDer(key.get());
  const auto unprotected = EncodeUnprotectedWithX5c(leaf_der);

  const auto cose = MakeCoseSign1WithX5c(protected_hdr, unprotected, payload, sig, false);

  cosesign1::validation::VerifyOptions opt;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::ES256;

  auto r = cosesign1::x509::VerifyCoseSign1WithX5c("X5cVerifier", cose, opt);
  REQUIRE(r.is_valid);
}

TEST_CASE("VerifyCoseSign1WithX5c succeeds with detached payload and external_payload option") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-7);
  const std::vector<std::uint8_t> payload = {9, 8, 7, 6, 5};

  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);

  const auto leaf_der = MakeSelfSignedCertDer(key.get());
  const auto unprotected = EncodeUnprotectedWithX5c(leaf_der);

  // payload is detached => encoded as null
  const auto cose = MakeCoseSign1WithX5c(protected_hdr, unprotected, payload, sig, true);

  cosesign1::validation::VerifyOptions opt;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::ES256;
  opt.external_payload = payload;

  auto r = cosesign1::x509::VerifyCoseSign1WithX5c("X5cVerifier", cose, opt);
  REQUIRE(r.is_valid);
}

TEST_CASE("VerifyCoseSign1WithX5c fails when missing x5c") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-7);
  const std::vector<std::uint8_t> payload = {1, 2, 3};

  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);

  const auto cose = cosesign1::tests::MakeCoseSign1(protected_hdr, false, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  auto r = cosesign1::x509::VerifyCoseSign1WithX5c("X5cVerifier", cose, opt);
  REQUIRE(!r.is_valid);
}

TEST_CASE("VerifyCoseSign1WithX5c succeeds when x5c is in protected headers") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const std::vector<std::uint8_t> payload = {1, 2, 3, 4};

  const auto leaf_der = MakeSelfSignedCertDer(key.get());
  const auto protected_map = EncodeProtectedAlgAndX5c(leaf_der);

  // Build signature over Sig_structure using the protected header bstr.
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_map, payload);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);

  // Unprotected map deliberately contains a non-integer key so unprotected scan fails,
  // forcing protected-header scan.
  std::vector<std::uint8_t> cose;
  {
    std::vector<std::uint8_t> buf(8192 + leaf_der.size());
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

      REQUIRE(cbor_encode_byte_string(&arr, protected_map.data(), protected_map.size()) == CborNoError);

      CborEncoder map;
      REQUIRE(cbor_encoder_create_map(&arr, &map, 1) == CborNoError);
      REQUIRE(cbor_encode_text_stringz(&map, "bogus") == CborNoError);
      REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
      REQUIRE(cbor_encoder_close_container(&arr, &map) == CborNoError);

      REQUIRE(cbor_encode_byte_string(&arr, payload.data(), payload.size()) == CborNoError);
      REQUIRE(cbor_encode_byte_string(&arr, sig.data(), sig.size()) == CborNoError);
      REQUIRE(cbor_encoder_close_container(&enc, &arr) == CborNoError);

      buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
      cose = buf;
      break;
    }
  }

  cosesign1::validation::VerifyOptions opt;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::ES256;

  auto r = cosesign1::x509::VerifyCoseSign1WithX5c("X5cVerifier", cose, opt);
  REQUIRE(r.is_valid);
}

TEST_CASE("VerifyCoseSign1WithX5c succeeds via protected raw-value fallback") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const std::vector<std::uint8_t> payload = {1, 2, 3, 4};

  const auto leaf_der = MakeSelfSignedCertDer(key.get());
  const auto protected_map = EncodeProtectedAlgAndX5cRawFallbackShape(leaf_der);

  const auto tbs = cosesign1::tests::BuildSigStructure(protected_map, payload);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);

  const auto cose = cosesign1::tests::MakeCoseSign1(protected_map, false, payload, sig);

  cosesign1::validation::VerifyOptions opt;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::ES256;

  auto r = cosesign1::x509::VerifyCoseSign1WithX5c("X5cVerifier", cose, opt);
  REQUIRE(r.is_valid);
}

TEST_CASE("VerifyCoseSign1WithX5c succeeds via unprotected raw-value fallback") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  // protected contains only alg
  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-7);
  const std::vector<std::uint8_t> payload = {9, 8, 7};
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);

  const auto leaf_der = MakeSelfSignedCertDer(key.get());
  const auto cose = MakeCoseSign1WithUnprotectedX5cIndefinite(protected_hdr, leaf_der, payload, sig, false);

  cosesign1::validation::VerifyOptions opt;
  opt.expected_alg = cosesign1::validation::CoseAlgorithm::ES256;

  auto r = cosesign1::x509::VerifyCoseSign1WithX5c("X5cVerifier", cose, opt);
  REQUIRE(r.is_valid);
}

TEST_CASE("VerifyCoseSign1WithX5c returns MISSING_X5C for invalid unprotected map shape") {
  // To hit the MISSING_X5C path we need TryExtractLeafDerFromHeaders to return false.
  // The current implementation returns true for a well-formed map even when x5c is absent,
  // so we force the protected header bstr to be empty (so protected scan can't succeed).
  const std::vector<std::uint8_t> protected_hdr;
  const std::vector<std::uint8_t> payload = {1, 2, 3};
  const std::vector<std::uint8_t> sig = {0x00};

  // Build COSE where unprotected map's key is not an integer.
  std::vector<std::uint8_t> cose;
  {
    std::vector<std::uint8_t> buf(4096);
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
      REQUIRE(cbor_encode_byte_string(&arr, nullptr, 0) == CborNoError);
      CborEncoder map;
      REQUIRE(cbor_encoder_create_map(&arr, &map, 1) == CborNoError);
      REQUIRE(cbor_encode_text_stringz(&map, "x5c") == CborNoError);
      REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
      REQUIRE(cbor_encoder_close_container(&arr, &map) == CborNoError);
      REQUIRE(cbor_encode_byte_string(&arr, payload.data(), payload.size()) == CborNoError);
      REQUIRE(cbor_encode_byte_string(&arr, sig.data(), sig.size()) == CborNoError);
      REQUIRE(cbor_encoder_close_container(&enc, &arr) == CborNoError);
      buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
      cose = buf;
      break;
    }
  }

  cosesign1::validation::VerifyOptions opt;
  auto r = cosesign1::x509::VerifyCoseSign1WithX5c("X5cVerifier", cose, opt);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(r.failures.size() >= 1);
  REQUIRE(r.failures[0].error_code.has_value());
  REQUIRE(*r.failures[0].error_code == "MISSING_X5C");
}

TEST_CASE("VerifyCoseSign1WithX5c returns MISSING_X5C on CBOR parse error") {
  const std::vector<std::uint8_t> not_cbor = {0x01, 0x02, 0x03};
  cosesign1::validation::VerifyOptions opt;

  auto r = cosesign1::x509::VerifyCoseSign1WithX5c("X5cVerifier", not_cbor, opt);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(r.failures.size() >= 1);
  REQUIRE(r.failures[0].error_code.has_value());
  REQUIRE(*r.failures[0].error_code == "MISSING_X5C");
}

TEST_CASE("VerifyCoseSign1WithX5c returns INVALID_X5C for empty leaf DER") {
  auto key = cosesign1::tests::GenerateEcP256Key();

  const auto protected_hdr = cosesign1::tests::MakeProtectedHeaderAlg(-7);
  const std::vector<std::uint8_t> payload = {1, 2, 3};
  const auto tbs = cosesign1::tests::BuildSigStructure(protected_hdr, payload);
  const auto sig = cosesign1::tests::SignEs256ToCoseRaw(key.get(), tbs);

  // unprotected: {33:[h'']}
  std::vector<std::uint8_t> cose;
  {
    std::vector<std::uint8_t> buf(4096);
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
      REQUIRE(cbor_encode_byte_string(&arr, protected_hdr.data(), protected_hdr.size()) == CborNoError);
      CborEncoder map;
      REQUIRE(cbor_encoder_create_map(&arr, &map, 1) == CborNoError);
      REQUIRE(cbor_encode_int(&map, 33) == CborNoError);
      CborEncoder x5c;
      REQUIRE(cbor_encoder_create_array(&map, &x5c, 1) == CborNoError);
      REQUIRE(cbor_encode_byte_string(&x5c, nullptr, 0) == CborNoError);
      REQUIRE(cbor_encoder_close_container(&map, &x5c) == CborNoError);
      REQUIRE(cbor_encoder_close_container(&arr, &map) == CborNoError);
      REQUIRE(cbor_encode_byte_string(&arr, payload.data(), payload.size()) == CborNoError);
      REQUIRE(cbor_encode_byte_string(&arr, sig.data(), sig.size()) == CborNoError);
      REQUIRE(cbor_encoder_close_container(&enc, &arr) == CborNoError);
      buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
      cose = buf;
      break;
    }
  }

  cosesign1::validation::VerifyOptions opt;
  auto r = cosesign1::x509::VerifyCoseSign1WithX5c("X5cVerifier", cose, opt);
  REQUIRE_FALSE(r.is_valid);
  REQUIRE(r.failures.size() >= 1);
  REQUIRE(r.failures[0].error_code.has_value());
  REQUIRE(*r.failures[0].error_code == "INVALID_X5C");
}
