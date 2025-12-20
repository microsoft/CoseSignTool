// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file test_mst_receipt_validation.cpp
 * @brief Unit tests for MST receipt parsing and verification.
 */

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <functional>
#include <fstream>

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>

#include <tinycbor/cbor.h>

#include <cosesign1/common/cbor_primitives.h>

#if defined(COSESIGN1_ENABLE_PQC)
#include <oqs/oqs.h>
#endif

#include "cosesign1/mst/mst_verifier.h"

namespace {

std::vector<std::uint8_t> ReadAllBytes(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  REQUIRE(f.good());
  std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  return bytes;
}

std::string ReadAllText(const std::string& path) {
  std::ifstream f(path, std::ios::binary);
  REQUIRE(f.good());
  std::string text((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
  return text;
}

bool HasErrorCode(const cosesign1::validation::ValidationResult& r, std::string_view code) {
  for (const auto& f : r.failures) {
    if (f.error_code && *f.error_code == code) {
      return true;
    }
  }
  return false;
}

std::string DescribeFailures(const cosesign1::validation::ValidationResult& r) {
  std::string out;
  for (const auto& f : r.failures) {
    out += "- ";
    if (f.error_code) {
      out += *f.error_code;
    } else {
      out += "(no error_code)";
    }
    out += ": ";
    out += f.message;
    out += "\n";
  }
  return out;
}

using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;
using EcKeyPtr = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;

EvpPkeyPtr GenerateEcP256Key() {
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  REQUIRE(pctx != nullptr);
  REQUIRE(EVP_PKEY_keygen_init(pctx) == 1);
  REQUIRE(EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_X9_62_prime256v1) == 1);

  EVP_PKEY* key = nullptr;
  REQUIRE(EVP_PKEY_keygen(pctx, &key) == 1);
  EVP_PKEY_CTX_free(pctx);
  return EvpPkeyPtr(key, &EVP_PKEY_free);
}

std::vector<std::uint8_t> Sha256(const std::vector<std::uint8_t>& data) {
  std::vector<std::uint8_t> out(32);
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  REQUIRE(ctx != nullptr);
  REQUIRE(EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1);
  REQUIRE(EVP_DigestUpdate(ctx, data.data(), data.size()) == 1);
  REQUIRE(EVP_DigestFinal_ex(ctx, out.data(), nullptr) == 1);
  EVP_MD_CTX_free(ctx);
  return out;
}

std::string Base64UrlEncode(const std::vector<std::uint8_t>& bytes) {
  std::string b64(((bytes.size() + 2) / 3) * 4, '\0');
  const int len = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(b64.data()), bytes.data(), static_cast<int>(bytes.size()));
  REQUIRE(len >= 0);
  b64.resize(static_cast<std::size_t>(len));

  for (char& c : b64) {
    if (c == '+') c = '-';
    else if (c == '/') c = '_';
  }

  while (!b64.empty() && b64.back() == '=') {
    b64.pop_back();
  }

  return b64;
}

cosesign1::mst::JwkEcPublicKey MakeP256JwkFromKey(EVP_PKEY* key, std::string kid) {
  EC_KEY* ec_raw = EVP_PKEY_get1_EC_KEY(key);
  REQUIRE(ec_raw != nullptr);
  EcKeyPtr ec(ec_raw, &EC_KEY_free);

  const EC_GROUP* group = EC_KEY_get0_group(ec.get());
  const EC_POINT* point = EC_KEY_get0_public_key(ec.get());
  REQUIRE(group != nullptr);
  REQUIRE(point != nullptr);

  const int degree = EC_GROUP_get_degree(group);
  REQUIRE(degree > 0);
  const std::size_t coord_size = (static_cast<std::size_t>(degree) + 7) / 8;

  BnPtr x(BN_new(), &BN_free);
  BnPtr y(BN_new(), &BN_free);
  REQUIRE(x != nullptr);
  REQUIRE(y != nullptr);
  REQUIRE(EC_POINT_get_affine_coordinates(group, point, x.get(), y.get(), nullptr) == 1);

  std::vector<std::uint8_t> x_bytes(coord_size);
  std::vector<std::uint8_t> y_bytes(coord_size);
  REQUIRE(BN_bn2binpad(x.get(), x_bytes.data(), static_cast<int>(x_bytes.size())) == static_cast<int>(x_bytes.size()));
  REQUIRE(BN_bn2binpad(y.get(), y_bytes.data(), static_cast<int>(y_bytes.size())) == static_cast<int>(y_bytes.size()));

  cosesign1::mst::JwkEcPublicKey jwk;
  jwk.kty = "EC";
  jwk.crv = "P-256";
  jwk.kid = std::move(kid);
  jwk.x_b64url = Base64UrlEncode(x_bytes);
  jwk.y_b64url = Base64UrlEncode(y_bytes);
  return jwk;
}

std::vector<std::uint8_t> EncodeMapAlgOnly(std::int64_t alg) {
  std::vector<std::uint8_t> buf(64);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, 1) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, alg) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeStatementNoUnprotected(const std::vector<std::uint8_t>& protected_headers_bstr,
                                                       const std::vector<std::uint8_t>& payload,
                                                       const std::vector<std::uint8_t>& signature) {
  std::vector<std::uint8_t> buf(256 + protected_headers_bstr.size() + payload.size() + signature.size());
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder arr;
    if (cbor_encoder_create_array(&enc, &arr, 4) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_byte_string(&arr, protected_headers_bstr.data(), protected_headers_bstr.size()) == CborNoError);
    CborEncoder empty;
    REQUIRE(cbor_encoder_create_map(&arr, &empty, 0) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&arr, &empty) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, payload.data(), payload.size()) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, signature.data(), signature.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &arr) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeInclusionProofMapBytes(const std::vector<std::uint8_t>& internal_tx_hash,
                                                       std::string_view evidence,
                                                       const std::vector<std::uint8_t>& data_hash) {
  // inclusion map is CBOR-encoded then wrapped as bstr in VDP.
  std::vector<std::uint8_t> buf(512);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);

    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, 2) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }

    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    CborEncoder leaf;
    REQUIRE(cbor_encoder_create_array(&map, &leaf, 3) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&leaf, internal_tx_hash.data(), internal_tx_hash.size()) == CborNoError);
    REQUIRE(cbor_encode_text_string(&leaf, evidence.data(), evidence.size()) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&leaf, data_hash.data(), data_hash.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &leaf) == CborNoError);

    REQUIRE(cbor_encode_int(&map, 2) == CborNoError);
    CborEncoder path;
    REQUIRE(cbor_encoder_create_array(&map, &path, 0) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &path) == CborNoError);

    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> BuildSigStructure(const std::vector<std::uint8_t>& protected_header_bstr,
                                            const std::vector<std::uint8_t>& external_payload) {
  std::vector<std::uint8_t> buf(256 + protected_header_bstr.size() + external_payload.size());
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder arr;
    if (cbor_encoder_create_array(&enc, &arr, 4) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_text_stringz(&arr, "Signature1") == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, protected_header_bstr.data(), protected_header_bstr.size()) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, nullptr, 0) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, external_payload.data(), external_payload.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &arr) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> SignEs256ToCoseRaw(EVP_PKEY* key, const std::vector<std::uint8_t>& to_be_signed) {
  EVP_MD_CTX* ctx = EVP_MD_CTX_new();
  REQUIRE(ctx != nullptr);
  REQUIRE(EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key) == 1);
  REQUIRE(EVP_DigestSignUpdate(ctx, to_be_signed.data(), to_be_signed.size()) == 1);

  size_t sig_len = 0;
  REQUIRE(EVP_DigestSignFinal(ctx, nullptr, &sig_len) == 1);
  std::vector<std::uint8_t> der(sig_len);
  REQUIRE(EVP_DigestSignFinal(ctx, der.data(), &sig_len) == 1);
  der.resize(sig_len);
  EVP_MD_CTX_free(ctx);

  const unsigned char* p = der.data();
  ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size()));
  REQUIRE(sig != nullptr);

  const BIGNUM* r = nullptr;
  const BIGNUM* s = nullptr;
  ECDSA_SIG_get0(sig, &r, &s);

  std::vector<std::uint8_t> raw(64);
  REQUIRE(BN_bn2binpad(r, raw.data(), 32) == 32);
  REQUIRE(BN_bn2binpad(s, raw.data() + 32, 32) == 32);
  ECDSA_SIG_free(sig);
  return raw;
}

std::vector<std::uint8_t> EncodeReceiptProtected(std::int64_t alg, std::string_view kid, std::string_view issuer) {
  std::vector<std::uint8_t> buf(256);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, CborIndefiniteLength) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, alg) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 4) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&map, reinterpret_cast<const std::uint8_t*>(kid.data()), kid.size()) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 395) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 2) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 15) == CborNoError);
    CborEncoder cwt;
    REQUIRE(cbor_encoder_create_map(&map, &cwt, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&cwt, 1) == CborNoError);
    REQUIRE(cbor_encode_text_string(&cwt, issuer.data(), issuer.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &cwt) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeReceiptProtectedCwtIssuerInt(std::int64_t alg, std::string_view kid, std::int64_t issuer_value) {
  // CWT map is present but issuer (key 1) is not a text string.
  std::vector<std::uint8_t> buf(256);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, CborIndefiniteLength) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, alg) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 4) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&map, reinterpret_cast<const std::uint8_t*>(kid.data()), kid.size()) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 395) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 2) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 15) == CborNoError);
    CborEncoder cwt;
    REQUIRE(cbor_encoder_create_map(&map, &cwt, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&cwt, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&cwt, issuer_value) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &cwt) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeReceiptProtectedCwtNoIssuer(std::int64_t alg, std::string_view kid) {
  // CWT map is present but does not contain issuer (key 1).
  std::vector<std::uint8_t> buf(256);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, CborIndefiniteLength) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, alg) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 4) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&map, reinterpret_cast<const std::uint8_t*>(kid.data()), kid.size()) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 395) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 2) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 15) == CborNoError);
    CborEncoder cwt;
    REQUIRE(cbor_encoder_create_map(&map, &cwt, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&cwt, 2) == CborNoError);
    REQUIRE(cbor_encode_text_stringz(&cwt, "not-issuer") == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &cwt) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeReceiptUnprotectedVdp(const std::vector<std::uint8_t>& inclusion_proof_map_bytes) {
  // unprotected map: { 396: { -1: [ bstr(inclusion_proof_map_bytes) ] } }
  std::vector<std::uint8_t> buf(512);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, 1) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_int(&map, 396) == CborNoError);
    CborEncoder vdp;
    REQUIRE(cbor_encoder_create_map(&map, &vdp, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&vdp, -1) == CborNoError);
    CborEncoder proofs;
    REQUIRE(cbor_encoder_create_array(&vdp, &proofs, 1) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&proofs, inclusion_proof_map_bytes.data(), inclusion_proof_map_bytes.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&vdp, &proofs) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &vdp) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeReceiptUnprotectedVdpNonMap() {
  // unprotected map: { 396: 1 } (VDP is not a map)
  std::vector<std::uint8_t> buf(64);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, 1) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_int(&map, 396) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeCoseSign1(const std::vector<std::uint8_t>& protected_headers_bstr,
                                         const std::vector<std::uint8_t>& unprotected_map_encoded,
                                         bool detached_payload,
                                         const std::vector<std::uint8_t>& payload,
                                         const std::vector<std::uint8_t>& signature) {
  const auto CopyCborValue = [](CborEncoder* out, CborValue* v, const auto& self) -> void {
    if (cbor_value_is_integer(v)) {
      std::int64_t i = 0;
      REQUIRE(cbor_value_get_int64(v, &i) == CborNoError);
      REQUIRE(cbor_value_advance_fixed(v) == CborNoError);
      REQUIRE(cbor_encode_int(out, i) == CborNoError);
      return;
    }

    if (cbor_value_is_byte_string(v)) {
      std::vector<std::uint8_t> bytes;
      REQUIRE(cosesign1::common::cbor::ReadByteString(v, bytes));
      REQUIRE(cbor_encode_byte_string(out, bytes.data(), bytes.size()) == CborNoError);
      return;
    }

    if (cbor_value_is_text_string(v)) {
      std::string text;
      REQUIRE(cosesign1::common::cbor::ReadTextString(v, text));
      REQUIRE(cbor_encode_text_string(out, text.data(), text.size()) == CborNoError);
      return;
    }

    if (cbor_value_is_boolean(v)) {
      bool b = false;
      REQUIRE(cbor_value_get_boolean(v, &b) == CborNoError);
      REQUIRE(cbor_value_advance_fixed(v) == CborNoError);
      REQUIRE(cbor_encode_boolean(out, b) == CborNoError);
      return;
    }

    if (cbor_value_is_null(v)) {
      REQUIRE(cbor_value_advance_fixed(v) == CborNoError);
      REQUIRE(cbor_encode_null(out) == CborNoError);
      return;
    }

    if (cbor_value_is_array(v)) {
      // Count elements (supports definite and indefinite arrays).
      std::size_t n = 0;
      {
        CborValue probe = *v;
        CborValue probe_it;
        REQUIRE(cbor_value_enter_container(&probe, &probe_it) == CborNoError);
        while (!cbor_value_at_end(&probe_it)) {
          ++n;
          REQUIRE(cosesign1::common::cbor::SkipAny(&probe_it));
        }
        (void)cbor_value_leave_container(&probe, &probe_it);
      }

      CborValue arr_it;
      REQUIRE(cbor_value_enter_container(v, &arr_it) == CborNoError);
      CborEncoder out_arr;
      REQUIRE(cbor_encoder_create_array(out, &out_arr, n) == CborNoError);
      while (!cbor_value_at_end(&arr_it)) {
        self(&out_arr, &arr_it, self);
      }
      REQUIRE(cbor_encoder_close_container(out, &out_arr) == CborNoError);
      REQUIRE(cbor_value_leave_container(v, &arr_it) == CborNoError);
      return;
    }

    if (cbor_value_is_map(v)) {
      // Count pairs (supports definite and indefinite maps).
      std::size_t pairs = 0;
      {
        CborValue probe = *v;
        CborValue probe_it;
        REQUIRE(cbor_value_enter_container(&probe, &probe_it) == CborNoError);
        while (!cbor_value_at_end(&probe_it)) {
          ++pairs;
          REQUIRE(cosesign1::common::cbor::SkipAny(&probe_it));
          REQUIRE(cosesign1::common::cbor::SkipAny(&probe_it));
        }
        (void)cbor_value_leave_container(&probe, &probe_it);
      }

      CborValue map_it;
      REQUIRE(cbor_value_enter_container(v, &map_it) == CborNoError);
      CborEncoder out_map;
      REQUIRE(cbor_encoder_create_map(out, &out_map, pairs) == CborNoError);
      while (!cbor_value_at_end(&map_it)) {
        self(&out_map, &map_it, self); // key
        self(&out_map, &map_it, self); // value
      }
      REQUIRE(cbor_encoder_close_container(out, &out_map) == CborNoError);
      REQUIRE(cbor_value_leave_container(v, &map_it) == CborNoError);
      return;
    }

    FAIL("Unsupported CBOR value shape in EncodeCoseSign1 helper");
  };

  std::vector<std::uint8_t> buf(512 + protected_headers_bstr.size() + unprotected_map_encoded.size() + payload.size() + signature.size());
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder arr;
    if (cbor_encoder_create_array(&enc, &arr, 4) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_byte_string(&arr, protected_headers_bstr.data(), protected_headers_bstr.size()) == CborNoError);

    // unprotected map (decode minimal and re-encode by copying raw bytes isn't supported; we parse and emit)
    {
      CborParser p;
      CborValue it;
      REQUIRE(cbor_parser_init(unprotected_map_encoded.data(), unprotected_map_encoded.size(), 0, &p, &it) == CborNoError);
      REQUIRE(cbor_value_is_map(&it));

      // For unit tests, re-encode by parsing and copying structure generically.
      CborValue map_it;
      REQUIRE(cbor_value_enter_container(&it, &map_it) == CborNoError);

      std::size_t pairs = 0;
      {
        CborValue tmp = map_it;
        while (!cbor_value_at_end(&tmp)) {
          ++pairs;
          REQUIRE(cosesign1::common::cbor::SkipAny(&tmp));
          REQUIRE(cosesign1::common::cbor::SkipAny(&tmp));
        }
      }

      CborEncoder out_map;
      REQUIRE(cbor_encoder_create_map(&arr, &out_map, pairs) == CborNoError);
      while (!cbor_value_at_end(&map_it)) {
        CopyCborValue(&out_map, &map_it, CopyCborValue); // key
        CopyCborValue(&out_map, &map_it, CopyCborValue); // value
      }
      REQUIRE(cbor_encoder_close_container(&arr, &out_map) == CborNoError);
      REQUIRE(cbor_value_leave_container(&it, &map_it) == CborNoError);
    }

    if (detached_payload) {
      REQUIRE(cbor_encode_null(&arr) == CborNoError);
    } else {
      REQUIRE(cbor_encode_byte_string(&arr, payload.data(), payload.size()) == CborNoError);
    }

    REQUIRE(cbor_encode_byte_string(&arr, signature.data(), signature.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &arr) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeStatementWithEmbeddedReceipt(const std::vector<std::uint8_t>& protected_headers_bstr,
                                                             const std::vector<std::uint8_t>& payload,
                                                             const std::vector<std::uint8_t>& signature,
                                                             const std::vector<std::uint8_t>& receipt_bytes) {
  std::vector<std::uint8_t> buf(512 + protected_headers_bstr.size() + payload.size() + signature.size() + receipt_bytes.size());
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder arr;
    if (cbor_encoder_create_array(&enc, &arr, 4) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_byte_string(&arr, protected_headers_bstr.data(), protected_headers_bstr.size()) == CborNoError);
    CborEncoder map;
    REQUIRE(cbor_encoder_create_map(&arr, &map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 394) == CborNoError);
    CborEncoder recs;
    REQUIRE(cbor_encoder_create_array(&map, &recs, 1) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&recs, receipt_bytes.data(), receipt_bytes.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &recs) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&arr, &map) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, payload.data(), payload.size()) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, signature.data(), signature.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &arr) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeStatementWithEmbeddedReceipts(const std::vector<std::uint8_t>& protected_headers_bstr,
                                                              const std::vector<std::uint8_t>& payload,
                                                              const std::vector<std::uint8_t>& signature,
                                                              const std::vector<std::vector<std::uint8_t>>& receipt_bytes_list) {
  std::size_t total = 0;
  for (const auto& r : receipt_bytes_list) total += r.size();

  std::vector<std::uint8_t> buf(1024 + protected_headers_bstr.size() + payload.size() + signature.size() + total);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder arr;
    if (cbor_encoder_create_array(&enc, &arr, 4) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_byte_string(&arr, protected_headers_bstr.data(), protected_headers_bstr.size()) == CborNoError);

    CborEncoder map;
    REQUIRE(cbor_encoder_create_map(&arr, &map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 394) == CborNoError);
    CborEncoder recs;
    REQUIRE(cbor_encoder_create_array(&map, &recs, static_cast<std::size_t>(receipt_bytes_list.size())) == CborNoError);
    for (const auto& receipt_bytes : receipt_bytes_list) {
      REQUIRE(cbor_encode_byte_string(&recs, receipt_bytes.data(), receipt_bytes.size()) == CborNoError);
    }
    REQUIRE(cbor_encoder_close_container(&map, &recs) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&arr, &map) == CborNoError);

    REQUIRE(cbor_encode_byte_string(&arr, payload.data(), payload.size()) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, signature.data(), signature.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &arr) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeEmptyMap() {
  std::vector<std::uint8_t> buf(16);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    const auto err = cbor_encoder_create_map(&enc, &map, 0);
    if (err != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeReceiptProtectedMissingIssuer(std::int64_t alg, std::string_view kid) {
  std::vector<std::uint8_t> buf(256);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, CborIndefiniteLength) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, alg) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 4) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&map, reinterpret_cast<const std::uint8_t*>(kid.data()), kid.size()) == CborNoError);
    // Intentionally omit label 15 (CWT) so issuer is unknown.
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeReceiptProtectedMinimalWithVdsAndPadding(std::int64_t alg,
                                                                         std::string_view kid,
                                                                         std::size_t padding_len) {
  // Small protected header suitable for receipt-only verification: {1: alg, 4: kid, 395: 2, 999: bstr(padding)}.
  // Note: issuer (CWT) is intentionally omitted.
  std::vector<std::uint8_t> buf(256 + padding_len);
  std::vector<std::uint8_t> padding(padding_len, 0x00);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, CborIndefiniteLength) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }

    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, alg) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 4) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&map, reinterpret_cast<const std::uint8_t*>(kid.data()), kid.size()) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 395) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 2) == CborNoError);

    if (padding_len > 0) {
      REQUIRE(cbor_encode_int(&map, 999) == CborNoError);
      REQUIRE(cbor_encode_byte_string(&map, padding.data(), padding.size()) == CborNoError);
    }

    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeStatementWithEmbeddedReceiptsArrayOfInts(const std::vector<std::uint8_t>& protected_headers_bstr,
                                                                         const std::vector<std::uint8_t>& payload,
                                                                         const std::vector<std::uint8_t>& signature) {
  // unprotected map: { 394: [ 1 ] } (array, but wrong element type)
  std::vector<std::uint8_t> buf(512 + protected_headers_bstr.size() + payload.size() + signature.size());
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder arr;
    if (cbor_encoder_create_array(&enc, &arr, 4) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_byte_string(&arr, protected_headers_bstr.data(), protected_headers_bstr.size()) == CborNoError);
    CborEncoder map;
    REQUIRE(cbor_encoder_create_map(&arr, &map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 394) == CborNoError);
    CborEncoder recs;
    REQUIRE(cbor_encoder_create_array(&map, &recs, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&recs, 1) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &recs) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&arr, &map) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, payload.data(), payload.size()) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, signature.data(), signature.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &arr) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeReceiptUnprotectedVdpCustom(const std::function<void(CborEncoder*)>& emit_vdp_map) {
  // unprotected map: { 396: <emit_vdp_map()> }
  std::vector<std::uint8_t> buf(512);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, 1) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_int(&map, 396) == CborNoError);
    emit_vdp_map(&map);
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeReceiptProtectedMissingKid(std::int64_t alg, std::string_view issuer) {
  std::vector<std::uint8_t> buf(256);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, CborIndefiniteLength) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, alg) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 395) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 2) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 15) == CborNoError);
    CborEncoder cwt;
    REQUIRE(cbor_encoder_create_map(&map, &cwt, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&cwt, 1) == CborNoError);
    REQUIRE(cbor_encode_text_string(&cwt, issuer.data(), issuer.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &cwt) == CborNoError);
    // Intentionally omit label 4 (kid).
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeReceiptProtectedWithVds(std::int64_t alg, std::string_view kid, std::string_view issuer, std::optional<std::int64_t> vds) {
  std::vector<std::uint8_t> buf(512);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, CborIndefiniteLength) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, alg) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 4) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&map, reinterpret_cast<const std::uint8_t*>(kid.data()), kid.size()) == CborNoError);
    if (vds.has_value()) {
      REQUIRE(cbor_encode_int(&map, 395) == CborNoError);
      REQUIRE(cbor_encode_int(&map, *vds) == CborNoError);
    }
    REQUIRE(cbor_encode_int(&map, 15) == CborNoError);
    CborEncoder cwt;
    REQUIRE(cbor_encoder_create_map(&map, &cwt, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&cwt, 1) == CborNoError);
    REQUIRE(cbor_encode_text_string(&cwt, issuer.data(), issuer.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &cwt) == CborNoError);

    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeReceiptUnprotectedVdpWithRawInclusionArray(std::size_t inclusion_count,
                                                                          const std::function<void(CborEncoder*)>& emit_inclusions_array_items) {
  // { 396: { -1: [ ... ] } }
  std::vector<std::uint8_t> buf(512);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, 1) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_int(&map, 396) == CborNoError);
    CborEncoder vdp;
    REQUIRE(cbor_encoder_create_map(&map, &vdp, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&vdp, -1) == CborNoError);
    CborEncoder arr;
    REQUIRE(cbor_encoder_create_array(&vdp, &arr, inclusion_count) == CborNoError);
    emit_inclusions_array_items(&arr);
    REQUIRE(cbor_encoder_close_container(&vdp, &arr) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &vdp) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeInclusionMapLeafAndPathCustom(bool include_leaf,
                                                              bool include_path,
                                                              const std::vector<std::uint8_t>& internal_tx_hash,
                                                              std::string_view evidence,
                                                              const std::vector<std::uint8_t>& data_hash,
                                                              const std::function<void(CborEncoder*)>& emit_path_value) {
  std::vector<std::uint8_t> buf(1024);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, CborIndefiniteLength) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }

    if (include_leaf) {
      REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
      CborEncoder leaf;
      REQUIRE(cbor_encoder_create_array(&map, &leaf, 3) == CborNoError);
      REQUIRE(cbor_encode_byte_string(&leaf, internal_tx_hash.data(), internal_tx_hash.size()) == CborNoError);
      // evidence is emitted as text by default
      REQUIRE(cbor_encode_text_string(&leaf, evidence.data(), evidence.size()) == CborNoError);
      REQUIRE(cbor_encode_byte_string(&leaf, data_hash.data(), data_hash.size()) == CborNoError);
      REQUIRE(cbor_encoder_close_container(&map, &leaf) == CborNoError);
    }

    if (include_path) {
      REQUIRE(cbor_encode_int(&map, 2) == CborNoError);
      emit_path_value(&map);
    }

    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeLeafArrayBytes(const std::vector<std::uint8_t>& internal_tx_hash,
                                               std::string_view evidence,
                                               const std::vector<std::uint8_t>& data_hash) {
  std::vector<std::uint8_t> buf(256 + internal_tx_hash.size() + evidence.size() + data_hash.size());
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder arr;
    if (cbor_encoder_create_array(&enc, &arr, 3) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_byte_string(&arr, internal_tx_hash.data(), internal_tx_hash.size()) == CborNoError);
    REQUIRE(cbor_encode_text_string(&arr, evidence.data(), evidence.size()) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, data_hash.data(), data_hash.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &arr) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeProofPathArrayBytes(const std::vector<std::pair<bool, std::vector<std::uint8_t>>>& elements) {
  std::vector<std::uint8_t> buf(256 + elements.size() * 64);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder outer;
    if (cbor_encoder_create_array(&enc, &outer, elements.size()) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }

    for (const auto& el : elements) {
      CborEncoder inner;
      REQUIRE(cbor_encoder_create_array(&outer, &inner, 2) == CborNoError);
      REQUIRE(cbor_encode_boolean(&inner, el.first) == CborNoError);
      REQUIRE(cbor_encode_byte_string(&inner, el.second.data(), el.second.size()) == CborNoError);
      REQUIRE(cbor_encoder_close_container(&outer, &inner) == CborNoError);
    }

    REQUIRE(cbor_encoder_close_container(&enc, &outer) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeInclusionMapLeafAndPathAsBstr(const std::vector<std::uint8_t>& leaf_bytes,
                                                              const std::vector<std::uint8_t>& path_bytes) {
  std::vector<std::uint8_t> buf(512 + leaf_bytes.size() + path_bytes.size());
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, 2) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }

    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&map, leaf_bytes.data(), leaf_bytes.size()) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 2) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&map, path_bytes.data(), path_bytes.size()) == CborNoError);

    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeStatementWithEmbeddedReceiptsIndefiniteArray(const std::vector<std::uint8_t>& protected_headers_bstr,
                                                                             const std::vector<std::uint8_t>& payload,
                                                                             const std::vector<std::uint8_t>& signature,
                                                                             const std::vector<std::vector<std::uint8_t>>& receipt_bytes_list) {
  std::size_t total = 0;
  for (const auto& r : receipt_bytes_list) total += r.size();

  std::vector<std::uint8_t> buf(1024 + protected_headers_bstr.size() + payload.size() + signature.size() + total);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder arr;
    if (cbor_encoder_create_array(&enc, &arr, 4) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_byte_string(&arr, protected_headers_bstr.data(), protected_headers_bstr.size()) == CborNoError);

    CborEncoder map;
    REQUIRE(cbor_encoder_create_map(&arr, &map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 394) == CborNoError);
    CborEncoder recs;
    REQUIRE(cbor_encoder_create_array(&map, &recs, CborIndefiniteLength) == CborNoError);
    for (const auto& receipt_bytes : receipt_bytes_list) {
      REQUIRE(cbor_encode_byte_string(&recs, receipt_bytes.data(), receipt_bytes.size()) == CborNoError);
    }
    REQUIRE(cbor_encoder_close_container(&map, &recs) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&arr, &map) == CborNoError);

    REQUIRE(cbor_encode_byte_string(&arr, payload.data(), payload.size()) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, signature.data(), signature.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &arr) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeStatementWithEmbeddedReceiptsWrongType(const std::vector<std::uint8_t>& protected_headers_bstr,
                                                                       const std::vector<std::uint8_t>& payload,
                                                                       const std::vector<std::uint8_t>& signature) {
  // unprotected map: { 394: 1 } (wrong type)
  std::vector<std::uint8_t> buf(512 + protected_headers_bstr.size() + payload.size() + signature.size());
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder arr;
    if (cbor_encoder_create_array(&enc, &arr, 4) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_byte_string(&arr, protected_headers_bstr.data(), protected_headers_bstr.size()) == CborNoError);
    CborEncoder map;
    REQUIRE(cbor_encoder_create_map(&arr, &map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 394) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&arr, &map) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, payload.data(), payload.size()) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&arr, signature.data(), signature.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &arr) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeReceiptProtectedKidWrongType(std::int64_t alg, std::string_view kid_text, std::string_view issuer) {
  // kid (label 4) is intentionally encoded as tstr to force raw-value fallback in ReadReceiptKid.
  std::vector<std::uint8_t> buf(512);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, CborIndefiniteLength) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, alg) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 4) == CborNoError);
    REQUIRE(cbor_encode_text_string(&map, kid_text.data(), kid_text.size()) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 395) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 2) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 15) == CborNoError);
    CborEncoder cwt;
    REQUIRE(cbor_encoder_create_map(&map, &cwt, 2) == CborNoError);
    // Add an unrelated key to force SkipAny branch in issuer parsing.
    REQUIRE(cbor_encode_int(&cwt, 99) == CborNoError);
    REQUIRE(cbor_encode_int(&cwt, 123) == CborNoError);
    REQUIRE(cbor_encode_int(&cwt, 1) == CborNoError);
    REQUIRE(cbor_encode_text_string(&cwt, issuer.data(), issuer.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &cwt) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeReceiptProtectedVdsWrongType(std::int64_t alg, std::string_view kid, std::string_view issuer) {
  // vds (label 395) is intentionally encoded as tstr to force raw-value fallback in ReadProtectedIntHeader.
  std::vector<std::uint8_t> buf(512);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, CborIndefiniteLength) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, alg) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 4) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&map, reinterpret_cast<const std::uint8_t*>(kid.data()), kid.size()) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 395) == CborNoError);
    REQUIRE(cbor_encode_text_stringz(&map, "2") == CborNoError);
    REQUIRE(cbor_encode_int(&map, 15) == CborNoError);
    CborEncoder cwt;
    REQUIRE(cbor_encoder_create_map(&map, &cwt, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&cwt, 1) == CborNoError);
    REQUIRE(cbor_encode_text_string(&cwt, issuer.data(), issuer.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &cwt) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

std::vector<std::uint8_t> EncodeReceiptUnprotectedVdpWithExtraKey(const std::vector<std::uint8_t>& inclusion_proof_map_bytes) {
  // unprotected map: { 396: { 123: 456, -1: [ bstr(inclusion_proof_map_bytes) ] } }
  std::vector<std::uint8_t> buf(768);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, 1) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_int(&map, 396) == CborNoError);
    CborEncoder vdp;
    REQUIRE(cbor_encoder_create_map(&map, &vdp, 2) == CborNoError);
    REQUIRE(cbor_encode_int(&vdp, 123) == CborNoError);
    REQUIRE(cbor_encode_int(&vdp, 456) == CborNoError);
    REQUIRE(cbor_encode_int(&vdp, -1) == CborNoError);
    CborEncoder proofs;
    REQUIRE(cbor_encoder_create_array(&vdp, &proofs, 1) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&proofs, inclusion_proof_map_bytes.data(), inclusion_proof_map_bytes.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&vdp, &proofs) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &vdp) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    return buf;
  }
}

} // namespace

namespace cosesign1::mst::internal {
void RunCoverageHooks_MstVerifier();
void RunCoverageHooks_JwkEcKey();
} // namespace cosesign1::mst::internal

TEST_CASE("MST: Coverage hooks") {
  cosesign1::mst::internal::RunCoverageHooks_MstVerifier();
  cosesign1::mst::internal::RunCoverageHooks_JwkEcKey();
}

TEST_CASE("MST: Azure SDK test vectors parse without crashing") {
  const auto transparent_statement = ReadAllBytes(
      "C:/src/repos/CoseSignTool/native/cosesign1-mst/tests/testdata/azure-sdk-for-net/transparent_statement.cose");

  // Empty keystore is fine because this test is about safe parsing.
  cosesign1::mst::OfflineEcKeyStore store;

  cosesign1::mst::VerificationOptions opts;
  // Avoid verifying any receipts; we only want to validate that parsing the statement and
  // extracting embedded receipts does not trigger TinyCBOR assertions/crashes.
  opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::IgnoreAll;
  opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAllMatching;

  auto res = cosesign1::mst::VerifyTransparentStatement("Mst", transparent_statement, store, opts);
  REQUIRE_FALSE(res.is_valid);
}

TEST_CASE("MST: Azure SDK receipt-only verification fails on KID mismatch") {
  const auto receipt = ReadAllBytes("C:/src/repos/CoseSignTool/native/cosesign1-mst/tests/testdata/azure-sdk-for-net/receipt.cose");
  const auto claims = ReadAllBytes(
      "C:/src/repos/CoseSignTool/native/cosesign1-mst/tests/testdata/azure-sdk-for-net/input_signed_claims");
  const auto jwks_json = ReadAllText(
      "C:/src/repos/CoseSignTool/native/cosesign1-mst/tests/testdata/azure-sdk-for-net/jwks_kid_mismatch.json");

  auto jwks = cosesign1::mst::ParseJwks(jwks_json);
  REQUIRE(jwks);
  REQUIRE_FALSE(jwks->keys.empty());

  // Ensure mst_verifier.cpp::ToLowerAscii takes the non-uppercase branch.
  // This should remain a mismatch against the receipt's KID.
  jwks->keys[0].kid = "kid-1";

  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwks->keys[0], receipt, claims);
  REQUIRE_FALSE(res.is_valid);
  INFO(DescribeFailures(res));
  REQUIRE(HasErrorCode(res, "MST_KID_MISMATCH"));
}

TEST_CASE("MST: Azure SDK receipt-only verification fails on claim digest mismatch") {
  const auto receipt = ReadAllBytes("C:/src/repos/CoseSignTool/native/cosesign1-mst/tests/testdata/azure-sdk-for-net/receipt.cose");
  auto claims = ReadAllBytes("C:/src/repos/CoseSignTool/native/cosesign1-mst/tests/testdata/azure-sdk-for-net/input_signed_claims");
  const auto jwks_json = ReadAllText(
      "C:/src/repos/CoseSignTool/native/cosesign1-mst/tests/testdata/azure-sdk-for-net/jwks_claim_digest_mismatch.json");

  const auto jwks = cosesign1::mst::ParseJwks(jwks_json);
  REQUIRE(jwks);
  REQUIRE_FALSE(jwks->keys.empty());
  REQUIRE_FALSE(claims.empty());

  // Tamper claims to force leaf data_hash != sha256(claims)
  claims.back() ^= 0x01;

  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwks->keys[0], receipt, claims);
  REQUIRE_FALSE(res.is_valid);
  INFO(DescribeFailures(res));
  REQUIRE(HasErrorCode(res, "MST_CLAIM_DIGEST_MISMATCH"));
}

TEST_CASE("MST: receipt-only VDP wrong type (int) yields MST_VDP_PARSE_ERROR") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string kid = "KiD1";
  cosesign1::mst::JwkEcPublicKey jwk = MakeP256JwkFromKey(key.get(), kid);

  const std::string issuer = "example.confidential-ledger.azure.com";
  const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdpNonMap();
  const std::vector<std::uint8_t> sig = {0x01};
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, sig);

  const std::vector<std::uint8_t> claims = {'c', 'l', 'a', 'i', 'm', 's'};
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, claims);
  REQUIRE_FALSE(res.is_valid);
  INFO(DescribeFailures(res));
  REQUIRE(HasErrorCode(res, "MST_VDP_PARSE_ERROR"));
}

TEST_CASE("MST: receipt issuer wrong type (int) is handled") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string kid = "kid";
  cosesign1::mst::JwkEcPublicKey jwk = MakeP256JwkFromKey(key.get(), kid);

  const auto receipt_protected = EncodeReceiptProtectedCwtIssuerInt(-7, "other-kid", 123);
  const std::vector<std::uint8_t> empty_map = {0xa0};
  const std::vector<std::uint8_t> sig = {0x01};
  const auto receipt = EncodeCoseSign1(receipt_protected, empty_map, true, {}, sig);

  const std::vector<std::uint8_t> claims = {1, 2, 3};
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, claims);
  REQUIRE_FALSE(res.is_valid);
}

TEST_CASE("MST: receipt issuer missing in CWT is handled") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string kid = "kid";
  cosesign1::mst::JwkEcPublicKey jwk = MakeP256JwkFromKey(key.get(), kid);

  const auto receipt_protected = EncodeReceiptProtectedCwtNoIssuer(-7, "other-kid");
  const std::vector<std::uint8_t> empty_map = {0xa0};
  const std::vector<std::uint8_t> sig = {0x01};
  const auto receipt = EncodeCoseSign1(receipt_protected, empty_map, true, {}, sig);

  const std::vector<std::uint8_t> claims = {1, 2, 3};
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, claims);
  REQUIRE_FALSE(res.is_valid);
}

TEST_CASE("MST: inclusion proof map enter_container failure yields MST_INCLUSION_PARSE_ERROR") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string kid = "KiD1";
  cosesign1::mst::JwkEcPublicKey jwk = MakeP256JwkFromKey(key.get(), kid);

  const std::string issuer = "example.confidential-ledger.azure.com";
  const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);

  // Truncated map: claims to have 1 pair but has no items.
  const std::vector<std::uint8_t> inclusion_map_bytes = {0xa1};
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_map_bytes);
  const std::vector<std::uint8_t> sig = {0x01};
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, sig);

  const std::vector<std::uint8_t> claims = {9, 9, 9};
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, claims);
  REQUIRE_FALSE(res.is_valid);
  INFO(DescribeFailures(res));
  REQUIRE(HasErrorCode(res, "MST_INCLUSION_PARSE_ERROR"));
}

TEST_CASE("MST: inclusion proof map SkipAny failure yields MST_INCLUSION_PARSE_ERROR") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string kid = "KiD1";
  cosesign1::mst::JwkEcPublicKey jwk = MakeP256JwkFromKey(key.get(), kid);

  const std::string issuer = "example.confidential-ledger.azure.com";
  const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);

  // Map(1): { 3: bstr(1) } but truncated before the byte-string payload.
  const std::vector<std::uint8_t> inclusion_map_bytes = {0xa1, 0x03, 0x41};
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_map_bytes);
  const std::vector<std::uint8_t> sig = {0x01};
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, sig);

  const std::vector<std::uint8_t> claims = {9, 9, 9};
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, claims);
  REQUIRE_FALSE(res.is_valid);
  INFO(DescribeFailures(res));
  REQUIRE(HasErrorCode(res, "MST_INCLUSION_PARSE_ERROR"));
}

TEST_CASE("MST: leaf bytes empty yields MST_LEAF_PARSE_ERROR") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string kid = "KiD1";
  cosesign1::mst::JwkEcPublicKey jwk = MakeP256JwkFromKey(key.get(), kid);

  const std::string issuer = "example.confidential-ledger.azure.com";
  const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);

  const std::vector<std::uint8_t> leaf_bytes; // empty => cbor_parser_init fails
  const auto path_bytes = EncodeProofPathArrayBytes({{true, std::vector<std::uint8_t>(32, 0x11)}});
  const auto inclusion_map_bytes = EncodeInclusionMapLeafAndPathAsBstr(leaf_bytes, path_bytes);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_map_bytes);
  const std::vector<std::uint8_t> sig = {0x01};
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, sig);

  const std::vector<std::uint8_t> claims = {1, 2, 3};
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, claims);
  REQUIRE_FALSE(res.is_valid);
  INFO(DescribeFailures(res));
  REQUIRE(HasErrorCode(res, "MST_LEAF_PARSE_ERROR"));
}

TEST_CASE("MST: leaf bytes truncated array header yields MST_LEAF_PARSE_ERROR") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string kid = "KiD1";
  cosesign1::mst::JwkEcPublicKey jwk = MakeP256JwkFromKey(key.get(), kid);

  const std::string issuer = "example.confidential-ledger.azure.com";
  const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);

  const std::vector<std::uint8_t> leaf_bytes = {0x83}; // array(3) but truncated
  const auto path_bytes = EncodeProofPathArrayBytes({{true, std::vector<std::uint8_t>(32, 0x11)}});
  const auto inclusion_map_bytes = EncodeInclusionMapLeafAndPathAsBstr(leaf_bytes, path_bytes);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_map_bytes);
  const std::vector<std::uint8_t> sig = {0x01};
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, sig);

  const std::vector<std::uint8_t> claims = {1, 2, 3};
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, claims);
  REQUIRE_FALSE(res.is_valid);
  INFO(DescribeFailures(res));
  REQUIRE(HasErrorCode(res, "MST_LEAF_PARSE_ERROR"));
}

TEST_CASE("MST: path bytes truncated array header yields MST_PATH_PARSE_ERROR") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string kid = "KiD1";
  cosesign1::mst::JwkEcPublicKey jwk = MakeP256JwkFromKey(key.get(), kid);

  const std::string issuer = "example.confidential-ledger.azure.com";
  const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);

  const auto leaf_ok = EncodeLeafArrayBytes(std::vector<std::uint8_t>(32, 0x11), "evidence", Sha256(std::vector<std::uint8_t>{1, 2, 3}));
  const std::vector<std::uint8_t> path_bytes = {0x81}; // array(1) but truncated
  const auto inclusion_map_bytes = EncodeInclusionMapLeafAndPathAsBstr(leaf_ok, path_bytes);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_map_bytes);
  const std::vector<std::uint8_t> sig = {0x01};
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, sig);

  const std::vector<std::uint8_t> claims = {1, 2, 3};
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, claims);
  REQUIRE_FALSE(res.is_valid);
  INFO(DescribeFailures(res));
  REQUIRE(HasErrorCode(res, "MST_PATH_PARSE_ERROR"));
}

TEST_CASE("MST: FailIfPresent uses unknown issuer prefix when issuer missing") {
  const std::string issuer = "example.confidential-ledger.azure.com";
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string kid = "test-kid";
  cosesign1::mst::OfflineEcKeyStore store;
  cosesign1::mst::JwksDocument jwks;
  jwks.keys.push_back(MakeP256JwkFromKey(key.get(), kid));
  store.AddIssuerKeys(issuer, jwks);

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p'};
  const std::vector<std::uint8_t> statement_signature = {0x01};

  const auto receipt_protected = EncodeReceiptProtectedMissingIssuer(-7, kid);
  const std::vector<std::uint8_t> empty_map = {0xa0};
  const std::vector<std::uint8_t> sig = {0x01};
  const auto receipt = EncodeCoseSign1(receipt_protected, empty_map, true, {}, sig);
  const auto statement = EncodeStatementWithEmbeddedReceipt(statement_protected, statement_payload, statement_signature, receipt);

  cosesign1::mst::VerificationOptions opts;
  opts.authorized_domains = {issuer};
  opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::FailIfPresent;
  opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAllMatching;

  const auto res = cosesign1::mst::VerifyTransparentStatement("Mst", statement, store, opts);
  REQUIRE_FALSE(res.is_valid);
  INFO(DescribeFailures(res));
  REQUIRE(HasErrorCode(res, "MST_UNAUTHORIZED_RECEIPT"));
}

TEST_CASE("MST: EcJwkToPublicKeyPem returns nullopt for empty x/y") {
  cosesign1::mst::JwkEcPublicKey jwk;
  jwk.kty = "EC";
  jwk.crv = "P-256";
  jwk.kid = "kid";
  jwk.x_b64url = "";
  jwk.y_b64url = "";
  const auto pem = cosesign1::mst::EcJwkToPublicKeyPem(jwk);
  REQUIRE_FALSE(pem);
}

TEST_CASE("MST: EcJwkToPublicKeyDer returns nullopt for point not on curve") {
  // x=y=0 is not a valid point on P-256, so EC_POINT_set_affine_coordinates should fail.
  cosesign1::mst::JwkEcPublicKey jwk;
  jwk.kty = "EC";
  jwk.crv = "P-256";
  jwk.kid = "kid";
  jwk.x_b64url = "AA";
  jwk.y_b64url = "AA";

  const auto der = cosesign1::mst::EcJwkToPublicKeyDer(jwk);
  REQUIRE_FALSE(der);
}

TEST_CASE("MST: empty input fails") {
  cosesign1::mst::OfflineEcKeyStore keys;
  cosesign1::mst::VerificationOptions opts;
  std::vector<std::uint8_t> statement;
  auto res = cosesign1::mst::VerifyTransparentStatement("Mst", statement, keys, opts);
  REQUIRE_FALSE(res.is_valid);
}

TEST_CASE("MST: valid single receipt verifies") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string kid = "test-kid";
  const std::string issuer = "example.confidential-ledger.azure.com";

  cosesign1::mst::OfflineEcKeyStore store;
  cosesign1::mst::JwksDocument jwks;
  jwks.keys.push_back(MakeP256JwkFromKey(key.get(), kid));
  store.AddIssuerKeys(issuer, jwks);

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y','l','o','a','d'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02, 0x03};
  const auto statement_no_unprotected = EncodeStatementNoUnprotected(statement_protected, statement_payload, statement_signature);
  const auto claims_digest = Sha256(statement_no_unprotected);

  std::vector<std::uint8_t> internal_tx_hash(32, 0x11);
  const std::string evidence = "evidence";
  const auto inclusion_map_bytes = EncodeInclusionProofMapBytes(internal_tx_hash, evidence, claims_digest);

  const auto evidence_bytes = std::vector<std::uint8_t>(evidence.begin(), evidence.end());
  const auto evidence_hash = Sha256(evidence_bytes);
  std::vector<std::uint8_t> leaf_hash_input;
  leaf_hash_input.insert(leaf_hash_input.end(), internal_tx_hash.begin(), internal_tx_hash.end());
  leaf_hash_input.insert(leaf_hash_input.end(), evidence_hash.begin(), evidence_hash.end());
  leaf_hash_input.insert(leaf_hash_input.end(), claims_digest.begin(), claims_digest.end());
  const auto accumulator = Sha256(leaf_hash_input);

  const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_map_bytes);
  const auto to_be_signed = BuildSigStructure(receipt_protected, accumulator);
  const auto receipt_signature = SignEs256ToCoseRaw(key.get(), to_be_signed);
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, receipt_signature);

  const auto transparent_statement = EncodeStatementWithEmbeddedReceipt(statement_protected, statement_payload, statement_signature, receipt);

  cosesign1::mst::VerificationOptions opts;
  opts.authorized_domains = {issuer};
  auto res = cosesign1::mst::VerifyTransparentStatement("Mst", transparent_statement, store, opts);
  REQUIRE(res.is_valid);
}

TEST_CASE("MST: unauthorized receipt fails by default") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string kid = "test-kid";
  const std::string issuer = "example.confidential-ledger.azure.com";

  cosesign1::mst::OfflineEcKeyStore store;
  cosesign1::mst::JwksDocument jwks;
  jwks.keys.push_back(MakeP256JwkFromKey(key.get(), kid));
  store.AddIssuerKeys(issuer, jwks);

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y','l','o','a','d'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02, 0x03};
  const auto statement_no_unprotected = EncodeStatementNoUnprotected(statement_protected, statement_payload, statement_signature);
  const auto claims_digest = Sha256(statement_no_unprotected);

  std::vector<std::uint8_t> internal_tx_hash(32, 0x11);
  const std::string evidence = "evidence";
  const auto inclusion_map_bytes = EncodeInclusionProofMapBytes(internal_tx_hash, evidence, claims_digest);

  const auto evidence_bytes = std::vector<std::uint8_t>(evidence.begin(), evidence.end());
  const auto evidence_hash = Sha256(evidence_bytes);
  std::vector<std::uint8_t> leaf_hash_input;
  leaf_hash_input.insert(leaf_hash_input.end(), internal_tx_hash.begin(), internal_tx_hash.end());
  leaf_hash_input.insert(leaf_hash_input.end(), evidence_hash.begin(), evidence_hash.end());
  leaf_hash_input.insert(leaf_hash_input.end(), claims_digest.begin(), claims_digest.end());
  const auto accumulator = Sha256(leaf_hash_input);

  const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_map_bytes);
  const auto to_be_signed = BuildSigStructure(receipt_protected, accumulator);
  const auto receipt_signature = SignEs256ToCoseRaw(key.get(), to_be_signed);
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, receipt_signature);

  const auto transparent_statement = EncodeStatementWithEmbeddedReceipt(statement_protected, statement_payload, statement_signature, receipt);

  cosesign1::mst::VerificationOptions opts;
  opts.authorized_domains = {"some.other.domain"};
  auto res = cosesign1::mst::VerifyTransparentStatement("Mst", transparent_statement, store, opts);
  REQUIRE_FALSE(res.is_valid);
}

#if defined(COSESIGN1_ENABLE_PQC)
namespace {
const char* OqsAlgFromCoseAlg(std::int64_t cose_alg) {
  switch (cose_alg) {
    case -48:
#if defined(OQS_SIG_alg_ml_dsa_44)
      return OQS_SIG_alg_ml_dsa_44;
#else
      return OQS_SIG_alg_dilithium_2;
#endif
    default:
      return nullptr;
  }
}

std::vector<std::uint8_t> SignMlDsa(std::int64_t cose_alg,
                                   const std::vector<std::uint8_t>& to_be_signed,
                                   const std::vector<std::uint8_t>& secret_key) {
  const char* alg = OqsAlgFromCoseAlg(cose_alg);
  REQUIRE(alg != nullptr);

  OQS_SIG* sig = OQS_SIG_new(alg);
  REQUIRE(sig != nullptr);

  REQUIRE(secret_key.size() == sig->length_secret_key);

  std::vector<std::uint8_t> out(sig->length_signature);
  std::size_t out_len = out.size();
  const auto rc = OQS_SIG_sign(sig,
                              out.data(),
                              &out_len,
                              to_be_signed.data(),
                              to_be_signed.size(),
                              secret_key.data());
  OQS_SIG_free(sig);
  REQUIRE(rc == OQS_SUCCESS);
  out.resize(out_len);
  return out;
}
} // namespace

TEST_CASE("MST: PQC ML-DSA receipt verifies") {
  constexpr std::int64_t cose_alg = -48; // ML-DSA-44

  const std::string kid = "pqc-test-kid";
  const std::string issuer = "example.confidential-ledger.azure.com";

  const char* oqs_alg = OqsAlgFromCoseAlg(cose_alg);
  REQUIRE(oqs_alg != nullptr);

  OQS_SIG* sig = OQS_SIG_new(oqs_alg);
  REQUIRE(sig != nullptr);

  std::vector<std::uint8_t> public_key(sig->length_public_key);
  std::vector<std::uint8_t> secret_key(sig->length_secret_key);
  REQUIRE(OQS_SIG_keypair(sig, public_key.data(), secret_key.data()) == OQS_SUCCESS);

  cosesign1::mst::OfflineEcKeyStore store;
  store.AddIssuerPublicKeyBytes(issuer,
                                kid,
                                cosesign1::validation::CoseAlgorithm::MLDsa44,
                                public_key);

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y','l','o','a','d'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02, 0x03};
  const auto statement_no_unprotected = EncodeStatementNoUnprotected(statement_protected, statement_payload, statement_signature);
  const auto claims_digest = Sha256(statement_no_unprotected);

  std::vector<std::uint8_t> internal_tx_hash(32, 0x11);
  const std::string evidence = "evidence";
  const auto inclusion_map_bytes = EncodeInclusionProofMapBytes(internal_tx_hash, evidence, claims_digest);

  const auto evidence_bytes = std::vector<std::uint8_t>(evidence.begin(), evidence.end());
  const auto evidence_hash = Sha256(evidence_bytes);
  std::vector<std::uint8_t> leaf_hash_input;
  leaf_hash_input.insert(leaf_hash_input.end(), internal_tx_hash.begin(), internal_tx_hash.end());
  leaf_hash_input.insert(leaf_hash_input.end(), evidence_hash.begin(), evidence_hash.end());
  leaf_hash_input.insert(leaf_hash_input.end(), claims_digest.begin(), claims_digest.end());
  const auto accumulator = Sha256(leaf_hash_input);

  const auto receipt_protected = EncodeReceiptProtected(cose_alg, kid, issuer);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_map_bytes);
  const auto to_be_signed = BuildSigStructure(receipt_protected, accumulator);
  const auto receipt_signature = SignMlDsa(cose_alg, to_be_signed, secret_key);

  // Receipt payload is detached.
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, receipt_signature);
  const auto transparent_statement = EncodeStatementWithEmbeddedReceipt(statement_protected, statement_payload, statement_signature, receipt);

  cosesign1::mst::VerificationOptions opts;
  opts.authorized_domains = {issuer};
  auto res = cosesign1::mst::VerifyTransparentStatement("Mst", transparent_statement, store, opts);
  INFO(DescribeFailures(res));
  REQUIRE(res.is_valid);

  OQS_SIG_free(sig);
}

#endif

TEST_CASE("MST: CBOR_PARSE_ERROR on invalid transparent statement") {
  cosesign1::mst::OfflineEcKeyStore keys;
  cosesign1::mst::VerificationOptions opts;
  opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::VerifyAll;
  opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAnyMatching;

  const std::vector<std::uint8_t> bad = {0x01, 0x02, 0x03};
  auto res = cosesign1::mst::VerifyTransparentStatement("Mst", bad, keys, opts);
  REQUIRE_FALSE(res.is_valid);
}

TEST_CASE("MST: MST_NO_RECEIPT when statement has no embedded receipts") {
  cosesign1::mst::OfflineEcKeyStore keys;
  cosesign1::mst::VerificationOptions opts;
  opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::VerifyAll;
  opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAnyMatching;

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_sig = {0x01};
  const auto no_receipts = EncodeStatementNoUnprotected(statement_protected, statement_payload, statement_sig);

  auto res = cosesign1::mst::VerifyTransparentStatement("Mst", no_receipts, keys, opts);
  REQUIRE_FALSE(res.is_valid);
  REQUIRE(HasErrorCode(res, "MST_NO_RECEIPT"));
}

TEST_CASE("MST: MST_UNKNOWN_ISSUER when receipt issuer missing") {
  const std::string kid = "kid";
  const std::string issuer = "example.confidential-ledger.azure.com";

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y','l','o','a','d'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};
  const auto statement_no_unprotected = EncodeStatementNoUnprotected(statement_protected, statement_payload, statement_signature);
  const auto claims_digest = Sha256(statement_no_unprotected);

  const auto receipt_protected = EncodeReceiptProtectedMissingIssuer(-7, kid);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(EncodeInclusionProofMapBytes(std::vector<std::uint8_t>(32, 0x11), "evidence", claims_digest));
  const std::vector<std::uint8_t> receipt_sig(64, 0x00);
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, receipt_sig);

  const auto transparent_statement = EncodeStatementWithEmbeddedReceipt(statement_protected, statement_payload, statement_signature, receipt);

  cosesign1::mst::OfflineEcKeyStore keys;
  cosesign1::mst::VerificationOptions opts;
  opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::VerifyAll;
  opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAnyMatching;
  opts.authorized_domains = {issuer};

  auto res = cosesign1::mst::VerifyTransparentStatement("Mst", transparent_statement, keys, opts);
  REQUIRE_FALSE(res.is_valid);
  REQUIRE(HasErrorCode(res, "MST_UNKNOWN_ISSUER"));
}

TEST_CASE("MST: MST_RECEIPT_PARSE_ERROR when embedded receipt is not COSE") {
  // This error code is emitted by VerifyReceiptAgainstStatement (receipt-only path).
  // For embedded receipts, parse failures are treated as "unknown issuer" and skipped.
  auto key = GenerateEcP256Key();
  REQUIRE(key);
  const std::string kid = "kid";
  const auto jwk = MakeP256JwkFromKey(key.get(), kid);

  const std::vector<std::uint8_t> bad_receipt = {0x01, 0x02, 0x03};
  const std::vector<std::uint8_t> claims = {'c','l','a','i','m','s'};

  auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, bad_receipt, claims);
  REQUIRE_FALSE(res.is_valid);
  REQUIRE(HasErrorCode(res, "MST_RECEIPT_PARSE_ERROR"));
}

TEST_CASE("MST: MST_KID_MISSING when receipt has no kid") {
  const std::string issuer = "example.confidential-ledger.azure.com";

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p'};
  const std::vector<std::uint8_t> statement_signature = {0x01};

  const auto receipt_protected = EncodeReceiptProtectedMissingKid(-7, issuer);
  const auto receipt = EncodeCoseSign1(receipt_protected, EncodeEmptyMap(), true, {}, std::vector<std::uint8_t>(64, 0x00));
  const auto transparent_statement = EncodeStatementWithEmbeddedReceipt(statement_protected, statement_payload, statement_signature, receipt);

  cosesign1::mst::OfflineEcKeyStore keys;
  cosesign1::mst::VerificationOptions opts;
  opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::VerifyAll;
  opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAnyMatching;

  auto res = cosesign1::mst::VerifyTransparentStatement("Mst", transparent_statement, keys, opts);
  REQUIRE_FALSE(res.is_valid);
  REQUIRE(HasErrorCode(res, "MST_KID_MISSING"));
}

TEST_CASE("MST: MST_KEY_NOT_FOUND when keystore missing kid") {
  const std::string kid = "missing";
  const std::string issuer = "example.confidential-ledger.azure.com";

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p'};
  const std::vector<std::uint8_t> statement_signature = {0x01};
  const auto statement_no_unprotected = EncodeStatementNoUnprotected(statement_protected, statement_payload, statement_signature);
  const auto claims_digest = Sha256(statement_no_unprotected);

  const auto receipt_protected = EncodeReceiptProtectedWithVds(-7, kid, issuer, 2);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(EncodeInclusionProofMapBytes(std::vector<std::uint8_t>(32, 0x11), "evidence", claims_digest));
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, std::vector<std::uint8_t>(64, 0x00));
  const auto transparent_statement = EncodeStatementWithEmbeddedReceipt(statement_protected, statement_payload, statement_signature, receipt);

  cosesign1::mst::OfflineEcKeyStore keys;
  cosesign1::mst::VerificationOptions opts;
  opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::VerifyAll;
  opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAnyMatching;

  auto res = cosesign1::mst::VerifyTransparentStatement("Mst", transparent_statement, keys, opts);
  REQUIRE_FALSE(res.is_valid);
  REQUIRE(HasErrorCode(res, "MST_KEY_NOT_FOUND"));
}

TEST_CASE("MST: VerifyReceiptAgainstStatement vds/vdp/inclusion/leaf/path error codes") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string kid = "test-kid";
  const std::string issuer = "example.confidential-ledger.azure.com";

  // Key store
  cosesign1::mst::OfflineEcKeyStore store;
  cosesign1::mst::JwksDocument jwks;
  jwks.keys.push_back(MakeP256JwkFromKey(key.get(), kid));
  store.AddIssuerKeys(issuer, jwks);

  // Base statement + digest
  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};
  const auto statement_no_unprotected = EncodeStatementNoUnprotected(statement_protected, statement_payload, statement_signature);
  const auto claims_digest = Sha256(statement_no_unprotected);
  const auto inclusion_ok = EncodeInclusionProofMapBytes(std::vector<std::uint8_t>(32, 0x11), "evidence", claims_digest);

  auto make_statement = [&](const std::vector<std::uint8_t>& receipt) {
    return EncodeStatementWithEmbeddedReceipt(statement_protected, statement_payload, statement_signature, receipt);
  };

  cosesign1::mst::VerificationOptions opts;
  opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::VerifyAll;
  opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAnyMatching;
  opts.authorized_domains = {issuer};

  // VDS missing
  {
    const auto phdr = EncodeReceiptProtectedWithVds(-7, kid, issuer, std::nullopt);
    const auto receipt = EncodeCoseSign1(phdr, EncodeEmptyMap(), true, {}, std::vector<std::uint8_t>(64, 0x00));
    auto res = cosesign1::mst::VerifyTransparentStatement("Mst", make_statement(receipt), store, opts);
    REQUIRE_FALSE(res.is_valid);
    REQUIRE(HasErrorCode(res, "MST_VDS_MISSING"));
  }

  // VDS not CCF
  {
    const auto phdr = EncodeReceiptProtectedWithVds(-7, kid, issuer, 999);
    const auto receipt = EncodeCoseSign1(phdr, EncodeEmptyMap(), true, {}, std::vector<std::uint8_t>(64, 0x00));
    auto res = cosesign1::mst::VerifyTransparentStatement("Mst", make_statement(receipt), store, opts);
    REQUIRE_FALSE(res.is_valid);
    REQUIRE(HasErrorCode(res, "MST_VDS_NOT_CCF"));
  }

  // VDP missing
  {
    const auto phdr = EncodeReceiptProtectedWithVds(-7, kid, issuer, 2);
    const auto receipt = EncodeCoseSign1(phdr, EncodeEmptyMap(), true, {}, std::vector<std::uint8_t>(64, 0x00));
    auto res = cosesign1::mst::VerifyTransparentStatement("Mst", make_statement(receipt), store, opts);
    REQUIRE_FALSE(res.is_valid);
    REQUIRE(HasErrorCode(res, "MST_VDP_MISSING"));
  }

  // Inclusion missing (empty -1 array)
  {
    const auto phdr = EncodeReceiptProtectedWithVds(-7, kid, issuer, 2);
    const auto unprot = EncodeReceiptUnprotectedVdpWithRawInclusionArray(0, [](CborEncoder*) {});
    const auto receipt = EncodeCoseSign1(phdr, unprot, true, {}, std::vector<std::uint8_t>(64, 0x00));
    auto res = cosesign1::mst::VerifyTransparentStatement("Mst", make_statement(receipt), store, opts);
    REQUIRE_FALSE(res.is_valid);
    REQUIRE(HasErrorCode(res, "MST_INCLUSION_MISSING"));
  }

  // Inclusion parse error (inclusion proof bytes are not a CBOR map)
  {
    const auto phdr = EncodeReceiptProtectedWithVds(-7, kid, issuer, 2);

    // Keep the array element as a bstr (so our EncodeCoseSign1 unprotected-header re-encoder
    // can safely copy it), but make the bytes decode to a non-map CBOR item.
    const std::vector<std::uint8_t> inclusion_not_a_map = {0x01};  // CBOR unsigned int 1
    const auto unprot = EncodeReceiptUnprotectedVdpWithRawInclusionArray(1, [&](CborEncoder* arr) {
      REQUIRE(cbor_encode_byte_string(arr, inclusion_not_a_map.data(), inclusion_not_a_map.size()) == CborNoError);
    });
    const auto receipt = EncodeCoseSign1(phdr, unprot, true, {}, std::vector<std::uint8_t>(64, 0x00));
    auto res = cosesign1::mst::VerifyTransparentStatement("Mst", make_statement(receipt), store, opts);
    REQUIRE_FALSE(res.is_valid);
    REQUIRE(HasErrorCode(res, "MST_INCLUSION_PARSE_ERROR"));
  }

  // Leaf parse error (leaf[1] not text)
  {
    const std::vector<std::uint8_t> internal_tx_hash(32, 0x11);
    const std::vector<std::uint8_t> data_hash(32, 0x22);
    const auto inclusion_bad_leaf = [&]() {
      std::vector<std::uint8_t> buf(256);
      while (true) {
        CborEncoder enc;
        cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
        CborEncoder map;
        if (cbor_encoder_create_map(&enc, &map, 2) != CborNoError) {
          buf.resize(buf.size() * 2);
          continue;
        }
        REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
        CborEncoder leaf;
        REQUIRE(cbor_encoder_create_array(&map, &leaf, 3) == CborNoError);
        REQUIRE(cbor_encode_byte_string(&leaf, internal_tx_hash.data(), internal_tx_hash.size()) == CborNoError);
        REQUIRE(cbor_encode_int(&leaf, 123) == CborNoError);
        REQUIRE(cbor_encode_byte_string(&leaf, data_hash.data(), data_hash.size()) == CborNoError);
        REQUIRE(cbor_encoder_close_container(&map, &leaf) == CborNoError);

        REQUIRE(cbor_encode_int(&map, 2) == CborNoError);
        CborEncoder path;
        REQUIRE(cbor_encoder_create_array(&map, &path, 0) == CborNoError);
        REQUIRE(cbor_encoder_close_container(&map, &path) == CborNoError);

        REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
        buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
        return buf;
      }
    }();

    const auto phdr = EncodeReceiptProtectedWithVds(-7, kid, issuer, 2);
    const auto unprot = EncodeReceiptUnprotectedVdpWithRawInclusionArray(1, [&](CborEncoder* arr) {
      REQUIRE(cbor_encode_byte_string(arr, inclusion_bad_leaf.data(), inclusion_bad_leaf.size()) == CborNoError);
    });
    const auto receipt = EncodeCoseSign1(phdr, unprot, true, {}, std::vector<std::uint8_t>(64, 0x00));
    auto res = cosesign1::mst::VerifyTransparentStatement("Mst", make_statement(receipt), store, opts);
    REQUIRE_FALSE(res.is_valid);
    REQUIRE(HasErrorCode(res, "MST_LEAF_PARSE_ERROR"));
  }

  // Path parse error (path is not array)
  {
    const std::vector<std::uint8_t> internal_tx_hash(32, 0x11);
    const std::vector<std::uint8_t> data_hash(32, 0x22);
    const auto inclusion_bad_path = EncodeInclusionMapLeafAndPathCustom(true,
                                                                        true,
                                                                        internal_tx_hash,
                                                                        "evidence",
                                                                        data_hash,
                                                                        [&](CborEncoder* map) {
                                                                          REQUIRE(cbor_encode_int(map, 123) == CborNoError);
                                                                        });

    const auto phdr = EncodeReceiptProtectedWithVds(-7, kid, issuer, 2);
    const auto unprot = EncodeReceiptUnprotectedVdpWithRawInclusionArray(1, [&](CborEncoder* arr) {
      REQUIRE(cbor_encode_byte_string(arr, inclusion_bad_path.data(), inclusion_bad_path.size()) == CborNoError);
    });
    const auto receipt = EncodeCoseSign1(phdr, unprot, true, {}, std::vector<std::uint8_t>(64, 0x00));
    auto res = cosesign1::mst::VerifyTransparentStatement("Mst", make_statement(receipt), store, opts);
    REQUIRE_FALSE(res.is_valid);
    REQUIRE(HasErrorCode(res, "MST_PATH_PARSE_ERROR"));
  }

  // Leaf missing
  {
    const std::vector<std::uint8_t> internal_tx_hash(32, 0x11);
    const std::vector<std::uint8_t> data_hash(32, 0x22);
    const auto inclusion_leaf_missing = EncodeInclusionMapLeafAndPathCustom(false,
                                                                            true,
                                                                            internal_tx_hash,
                                                                            "evidence",
                                                                            data_hash,
                                                                            [&](CborEncoder* map) {
                                                                              CborEncoder path;
                                                                              REQUIRE(cbor_encoder_create_array(map, &path, 0) == CborNoError);
                                                                              REQUIRE(cbor_encoder_close_container(map, &path) == CborNoError);
                                                                            });

    const auto phdr = EncodeReceiptProtectedWithVds(-7, kid, issuer, 2);
    const auto unprot = EncodeReceiptUnprotectedVdpWithRawInclusionArray(1, [&](CborEncoder* arr) {
      REQUIRE(cbor_encode_byte_string(arr, inclusion_leaf_missing.data(), inclusion_leaf_missing.size()) == CborNoError);
    });
    const auto receipt = EncodeCoseSign1(phdr, unprot, true, {}, std::vector<std::uint8_t>(64, 0x00));
    auto res = cosesign1::mst::VerifyTransparentStatement("Mst", make_statement(receipt), store, opts);
    REQUIRE_FALSE(res.is_valid);
    REQUIRE(HasErrorCode(res, "MST_LEAF_MISSING"));
  }

  // Path missing
  {
    const std::vector<std::uint8_t> internal_tx_hash(32, 0x11);
    const std::vector<std::uint8_t> data_hash(32, 0x22);
    const auto inclusion_path_missing = EncodeInclusionMapLeafAndPathCustom(true,
                                                                            false,
                                                                            internal_tx_hash,
                                                                            "evidence",
                                                                            data_hash,
                                                                            [&](CborEncoder*) {});

    const auto phdr = EncodeReceiptProtectedWithVds(-7, kid, issuer, 2);
    const auto unprot = EncodeReceiptUnprotectedVdpWithRawInclusionArray(1, [&](CborEncoder* arr) {
      REQUIRE(cbor_encode_byte_string(arr, inclusion_path_missing.data(), inclusion_path_missing.size()) == CborNoError);
    });
    const auto receipt = EncodeCoseSign1(phdr, unprot, true, {}, std::vector<std::uint8_t>(64, 0x00));
    auto res = cosesign1::mst::VerifyTransparentStatement("Mst", make_statement(receipt), store, opts);
    REQUIRE_FALSE(res.is_valid);
    REQUIRE(HasErrorCode(res, "MST_PATH_MISSING"));
  }

  // Receipt signature invalid (correct structure, wrong signature)
  {
    const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);
    const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_ok);
    const auto tbs = BuildSigStructure(receipt_protected, Sha256(std::vector<std::uint8_t>(32, 0x00)));
    (void)tbs;

    auto receipt_signature = std::vector<std::uint8_t>(64, 0x00);
    receipt_signature[0] ^= 0x01;
    const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, receipt_signature);
    auto res = cosesign1::mst::VerifyTransparentStatement("Mst", make_statement(receipt), store, opts);
    REQUIRE_FALSE(res.is_valid);
    REQUIRE(HasErrorCode(res, "MST_RECEIPT_SIGNATURE_INVALID"));
  }
}

TEST_CASE("MST: authorized receipt behavior variants") {
  auto key1 = GenerateEcP256Key();
  auto key2 = GenerateEcP256Key();
  REQUIRE(key1);
  REQUIRE(key2);

  const std::string issuer1 = "issuer1.confidential-ledger.azure.com";
  const std::string issuer2 = "issuer2.confidential-ledger.azure.com";
  const std::string kid1 = "kid1";
  const std::string kid2 = "kid2";

  cosesign1::mst::OfflineEcKeyStore store;
  {
    cosesign1::mst::JwksDocument jwks;
    jwks.keys.push_back(MakeP256JwkFromKey(key1.get(), kid1));
    store.AddIssuerKeys(issuer1, jwks);
  }
  {
    cosesign1::mst::JwksDocument jwks;
    jwks.keys.push_back(MakeP256JwkFromKey(key2.get(), kid2));
    store.AddIssuerKeys(issuer2, jwks);
  }

  // Statement digest base
  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};
  const auto statement_no_unprotected = EncodeStatementNoUnprotected(statement_protected, statement_payload, statement_signature);
  const auto claims_digest = Sha256(statement_no_unprotected);

  const std::vector<std::uint8_t> internal_tx_hash(32, 0x11);
  const std::string evidence = "evidence";
  const auto inclusion_map_bytes = EncodeInclusionProofMapBytes(internal_tx_hash, evidence, claims_digest);

  auto make_valid_receipt = [&](EVP_PKEY* key, std::string_view kid, std::string_view issuer) {
    const auto evidence_bytes = std::vector<std::uint8_t>(evidence.begin(), evidence.end());
    const auto evidence_hash = Sha256(evidence_bytes);
    std::vector<std::uint8_t> leaf_hash_input;
    leaf_hash_input.insert(leaf_hash_input.end(), internal_tx_hash.begin(), internal_tx_hash.end());
    leaf_hash_input.insert(leaf_hash_input.end(), evidence_hash.begin(), evidence_hash.end());
    leaf_hash_input.insert(leaf_hash_input.end(), claims_digest.begin(), claims_digest.end());
    const auto accumulator = Sha256(leaf_hash_input);

    const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);
    const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_map_bytes);
    const auto to_be_signed = BuildSigStructure(receipt_protected, accumulator);
    const auto receipt_signature = SignEs256ToCoseRaw(key, to_be_signed);
    return EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, receipt_signature);
  };

  auto make_invalid_sig_receipt = [&](EVP_PKEY* key, std::string_view kid, std::string_view issuer) {
    auto r = make_valid_receipt(key, kid, issuer);
    if (!r.empty()) {
      r.back() ^= 0x01;
    }
    return r;
  };

  const auto receipt1_ok = make_valid_receipt(key1.get(), kid1, issuer1);
  const auto receipt2_bad = make_invalid_sig_receipt(key2.get(), kid2, issuer2);
  const auto stmt_two = EncodeStatementWithEmbeddedReceipts(statement_protected, statement_payload, statement_signature, {receipt1_ok, receipt2_bad});

  // VerifyAllMatching: issuer2 failure should surface as required domain failed.
  {
    cosesign1::mst::VerificationOptions opts;
    opts.authorized_domains = {issuer1, issuer2};
    opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::IgnoreAll;
    opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAllMatching;
    auto res = cosesign1::mst::VerifyTransparentStatement("Mst", stmt_two, store, opts);
    REQUIRE_FALSE(res.is_valid);
    REQUIRE(HasErrorCode(res, "MST_REQUIRED_DOMAIN_FAILED"));
  }

  // VerifyAnyMatching: one valid authorized receipt should clear other authorized failures.
  {
    cosesign1::mst::VerificationOptions opts;
    opts.authorized_domains = {issuer1, issuer2};
    opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::IgnoreAll;
    opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAnyMatching;
    auto res = cosesign1::mst::VerifyTransparentStatement("Mst", stmt_two, store, opts);
    INFO(DescribeFailures(res));
    REQUIRE(res.is_valid);
  }

  // RequireAll: missing issuer2 receipt should fail.
  {
    const auto stmt_one = EncodeStatementWithEmbeddedReceipt(statement_protected, statement_payload, statement_signature, receipt1_ok);
    cosesign1::mst::VerificationOptions opts;
    opts.authorized_domains = {issuer1, issuer2};
    opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::IgnoreAll;
    opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::RequireAll;
    auto res = cosesign1::mst::VerifyTransparentStatement("Mst", stmt_one, store, opts);
    REQUIRE_FALSE(res.is_valid);
    REQUIRE(HasErrorCode(res, "MST_REQUIRED_DOMAIN_MISSING"));
  }

  // VerifyAllMatching: no receipts for authorized domains.
  {
    const auto receipt_unauth = make_valid_receipt(key2.get(), kid2, issuer2);
    const auto stmt_unauth = EncodeStatementWithEmbeddedReceipt(statement_protected, statement_payload, statement_signature, receipt_unauth);
    cosesign1::mst::VerificationOptions opts;
    opts.authorized_domains = {issuer1};
    opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::IgnoreAll;
    opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAllMatching;
    auto res = cosesign1::mst::VerifyTransparentStatement("Mst", stmt_unauth, store, opts);
    REQUIRE_FALSE(res.is_valid);
    REQUIRE(HasErrorCode(res, "MST_NO_VALID_AUTHORIZED_RECEIPTS"));
  }
}

TEST_CASE("MST: JWKS parsing and key conversion error paths") {
  REQUIRE_FALSE(cosesign1::mst::ParseJwks("not json").has_value());
  REQUIRE_FALSE(cosesign1::mst::ParseJwks("{\"keys\":{}}" ).has_value());

  // No valid keys should return nullopt.
  REQUIRE_FALSE(cosesign1::mst::ParseJwks("{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"1\"}]}" ).has_value());

  cosesign1::mst::JwkEcPublicKey jwk;
  jwk.kty = "EC";
  jwk.crv = "P-256";
  jwk.kid = "kid";
  jwk.x_b64url = "!!!";
  jwk.y_b64url = "!!!";
  REQUIRE_FALSE(cosesign1::mst::EcJwkToPublicKeyPem(jwk).has_value());

  // Unsupported curve should fail early.
  jwk.crv = "P-999";
  jwk.x_b64url = "AA";
  jwk.y_b64url = "AA";
  REQUIRE_FALSE(cosesign1::mst::EcJwkToPublicKeyPem(jwk).has_value());

  // Exercise Base64UrlDecode '=' trimming logic by using inputs that require '==' padding.
  jwk.crv = "P-256";
  jwk.x_b64url = Base64UrlEncode(std::vector<std::uint8_t>(31, 0x01));
  jwk.y_b64url = Base64UrlEncode(std::vector<std::uint8_t>(31, 0x02));
  REQUIRE_FALSE(cosesign1::mst::EcJwkToPublicKeyPem(jwk).has_value());

  // Exercise Base64UrlDecode character mapping: '-' -> '+', '_' -> '/', '=' ignored.
  // This input is not expected to be a valid point on the curve; we only care that decoding paths execute.
  jwk.kty = "EC";
  jwk.crv = "P-256";
  jwk.kid = "kid";
  jwk.x_b64url = "__=="; // '_' and '='
  jwk.y_b64url = "----"; // '-'
  REQUIRE_FALSE(cosesign1::mst::EcJwkToPublicKeyPem(jwk).has_value());

  // Success path: valid JWK derived from a real P-256 key converts to DER.
  {
    auto key = GenerateEcP256Key();
    REQUIRE(key);

    const auto good = MakeP256JwkFromKey(key.get(), "good2");

    const auto pem = cosesign1::mst::EcJwkToPublicKeyPem(good);
    REQUIRE(pem.has_value());
    REQUIRE(pem->find("BEGIN PUBLIC KEY") != std::string::npos);

    const auto der = cosesign1::mst::EcJwkToPublicKeyDer(good);
    REQUIRE(der.has_value());
    REQUIRE_FALSE(der->empty());
    // SPKI DER should start with SEQUENCE (0x30).
    REQUIRE((*der)[0] == 0x30);
  }

  // ExpectedAlgFromCrv: case-insensitivity and unknown curve.
  REQUIRE(cosesign1::mst::ExpectedAlgFromCrv("p-256").has_value());
  REQUIRE_FALSE(cosesign1::mst::ExpectedAlgFromCrv("p-999").has_value());

  REQUIRE(cosesign1::mst::ExpectedAlgFromCrv("P-521").has_value());
  REQUIRE(*cosesign1::mst::ExpectedAlgFromCrv("P-521") == cosesign1::validation::CoseAlgorithm::ES512);

  // AddIssuerKeys should skip keys that fail PEM conversion.
  {
    auto key = GenerateEcP256Key();
    REQUIRE(key);

    cosesign1::mst::JwksDocument jwks;
    jwks.keys.push_back(MakeP256JwkFromKey(key.get(), "good"));

    cosesign1::mst::JwkEcPublicKey bad;
    bad.kty = "EC";
    bad.crv = "P-256";
    bad.kid = "bad";
    bad.x_b64url = "!!!";
    bad.y_b64url = "!!!";
    jwks.keys.push_back(std::move(bad));

    cosesign1::mst::OfflineEcKeyStore keys;
    keys.AddIssuerKeys("issuer", std::move(jwks));

    REQUIRE(keys.Resolve("issuer", "good").has_value());
    REQUIRE_FALSE(keys.Resolve("issuer", "bad").has_value());
  }

  cosesign1::mst::OfflineEcKeyStore store;
  REQUIRE_FALSE(store.Resolve("issuer", "kid").has_value());
}

TEST_CASE("MST: receipt inclusion proof with non-empty path verifies") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string issuer = "example.confidential-ledger.azure.com";
  const std::string kid = "kid";

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};
  const auto statement_no_unprotected = EncodeStatementNoUnprotected(statement_protected, statement_payload, statement_signature);
  const auto claims_digest = Sha256(statement_no_unprotected);

  const std::vector<std::uint8_t> internal_tx_hash(32, 0x11);
  const std::string evidence = "evidence";
  const auto evidence_bytes = std::vector<std::uint8_t>(evidence.begin(), evidence.end());
  const auto evidence_hash = Sha256(evidence_bytes);

  const std::vector<std::uint8_t> h1(32, 0xA1);
  const std::vector<std::uint8_t> h2(32, 0xB2);

  const auto inclusion_map_bytes = EncodeInclusionMapLeafAndPathCustom(true,
                                                                        true,
                                                                        internal_tx_hash,
                                                                        evidence,
                                                                        claims_digest,
                                                                        [&](CborEncoder* map) {
                                                                          CborEncoder path;
                                                                          REQUIRE(cbor_encoder_create_array(map, &path, 2) == CborNoError);
                                                                          {
                                                                            CborEncoder el;
                                                                            REQUIRE(cbor_encoder_create_array(&path, &el, 2) == CborNoError);
                                                                            REQUIRE(cbor_encode_boolean(&el, true) == CborNoError);
                                                                            REQUIRE(cbor_encode_byte_string(&el, h1.data(), h1.size()) == CborNoError);
                                                                            REQUIRE(cbor_encoder_close_container(&path, &el) == CborNoError);
                                                                          }
                                                                          {
                                                                            CborEncoder el;
                                                                            REQUIRE(cbor_encoder_create_array(&path, &el, 2) == CborNoError);
                                                                            REQUIRE(cbor_encode_boolean(&el, false) == CborNoError);
                                                                            REQUIRE(cbor_encode_byte_string(&el, h2.data(), h2.size()) == CborNoError);
                                                                            REQUIRE(cbor_encoder_close_container(&path, &el) == CborNoError);
                                                                          }
                                                                          REQUIRE(cbor_encoder_close_container(map, &path) == CborNoError);
                                                                        });

  // Compute accumulator to match verifier logic.
  std::vector<std::uint8_t> leaf_hash_input;
  leaf_hash_input.insert(leaf_hash_input.end(), internal_tx_hash.begin(), internal_tx_hash.end());
  leaf_hash_input.insert(leaf_hash_input.end(), evidence_hash.begin(), evidence_hash.end());
  leaf_hash_input.insert(leaf_hash_input.end(), claims_digest.begin(), claims_digest.end());
  auto accumulator = Sha256(leaf_hash_input);
  {
    std::vector<std::uint8_t> in;
    in.insert(in.end(), h1.begin(), h1.end());
    in.insert(in.end(), accumulator.begin(), accumulator.end());
    accumulator = Sha256(in);
  }
  {
    std::vector<std::uint8_t> in;
    in.insert(in.end(), accumulator.begin(), accumulator.end());
    in.insert(in.end(), h2.begin(), h2.end());
    accumulator = Sha256(in);
  }

  const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_map_bytes);
  const auto to_be_signed = BuildSigStructure(receipt_protected, accumulator);
  const auto receipt_signature = SignEs256ToCoseRaw(key.get(), to_be_signed);
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, receipt_signature);

  // Use mixed-case expected kid to exercise ToLowerAscii uppercase branch.
  const auto jwk = MakeP256JwkFromKey(key.get(), "KiD");
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, statement_no_unprotected);
  INFO(DescribeFailures(res));
  REQUIRE(res.is_valid);
}

TEST_CASE("MST: receipt inclusion proof leaf/path as byte strings verifies") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string issuer = "example.confidential-ledger.azure.com";
  const std::string kid = "kid";

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};
  const auto statement_no_unprotected = EncodeStatementNoUnprotected(statement_protected, statement_payload, statement_signature);
  const auto claims_digest = Sha256(statement_no_unprotected);

  const std::vector<std::uint8_t> internal_tx_hash(32, 0x22);
  const std::string evidence = "evidence";
  const auto evidence_bytes = std::vector<std::uint8_t>(evidence.begin(), evidence.end());
  const auto evidence_hash = Sha256(evidence_bytes);

  const std::vector<std::uint8_t> h1(32, 0xC3);
  const std::vector<std::uint8_t> h2(32, 0xD4);
  const auto leaf_bytes = EncodeLeafArrayBytes(internal_tx_hash, evidence, claims_digest);
  const auto path_bytes = EncodeProofPathArrayBytes({{true, h1}, {false, h2}});
  const auto inclusion_map_bytes = EncodeInclusionMapLeafAndPathAsBstr(leaf_bytes, path_bytes);

  // Compute accumulator to match verifier logic.
  std::vector<std::uint8_t> leaf_hash_input;
  leaf_hash_input.insert(leaf_hash_input.end(), internal_tx_hash.begin(), internal_tx_hash.end());
  leaf_hash_input.insert(leaf_hash_input.end(), evidence_hash.begin(), evidence_hash.end());
  leaf_hash_input.insert(leaf_hash_input.end(), claims_digest.begin(), claims_digest.end());
  auto accumulator = Sha256(leaf_hash_input);
  {
    std::vector<std::uint8_t> in;
    in.insert(in.end(), h1.begin(), h1.end());
    in.insert(in.end(), accumulator.begin(), accumulator.end());
    accumulator = Sha256(in);
  }
  {
    std::vector<std::uint8_t> in;
    in.insert(in.end(), accumulator.begin(), accumulator.end());
    in.insert(in.end(), h2.begin(), h2.end());
    accumulator = Sha256(in);
  }

  const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_map_bytes);
  const auto to_be_signed = BuildSigStructure(receipt_protected, accumulator);
  const auto receipt_signature = SignEs256ToCoseRaw(key.get(), to_be_signed);
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, receipt_signature);

  const auto jwk = MakeP256JwkFromKey(key.get(), kid);
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, statement_no_unprotected);
  INFO(DescribeFailures(res));
  REQUIRE(res.is_valid);
}

TEST_CASE("MST: unauthorized receipt behavior FailIfPresent rejects") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string issuer = "unauthorized.confidential-ledger.azure.com";
  const std::string kid = "kid";

  cosesign1::mst::OfflineEcKeyStore store;
  {
    cosesign1::mst::JwksDocument jwks;
    jwks.keys.push_back(MakeP256JwkFromKey(key.get(), kid));
    store.AddIssuerKeys(issuer, jwks);
  }

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};
  const auto statement_no_unprotected = EncodeStatementNoUnprotected(statement_protected, statement_payload, statement_signature);
  const auto claims_digest = Sha256(statement_no_unprotected);

  const std::vector<std::uint8_t> internal_tx_hash(32, 0x11);
  const std::string evidence = "evidence";
  const auto inclusion_map_bytes = EncodeInclusionProofMapBytes(internal_tx_hash, evidence, claims_digest);

  // Build a valid receipt.
  const auto evidence_bytes = std::vector<std::uint8_t>(evidence.begin(), evidence.end());
  const auto evidence_hash = Sha256(evidence_bytes);
  std::vector<std::uint8_t> leaf_hash_input;
  leaf_hash_input.insert(leaf_hash_input.end(), internal_tx_hash.begin(), internal_tx_hash.end());
  leaf_hash_input.insert(leaf_hash_input.end(), evidence_hash.begin(), evidence_hash.end());
  leaf_hash_input.insert(leaf_hash_input.end(), claims_digest.begin(), claims_digest.end());
  const auto accumulator = Sha256(leaf_hash_input);

  const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_map_bytes);
  const auto to_be_signed = BuildSigStructure(receipt_protected, accumulator);
  const auto receipt_signature = SignEs256ToCoseRaw(key.get(), to_be_signed);
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, receipt_signature);

  const auto statement = EncodeStatementWithEmbeddedReceipt(statement_protected, statement_payload, statement_signature, receipt);

  cosesign1::mst::VerificationOptions opts;
  opts.authorized_domains = {"some-other.confidential-ledger.azure.com"};
  opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::FailIfPresent;
  opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAnyMatching;

  const auto res = cosesign1::mst::VerifyTransparentStatement("Mst", statement, store, opts);
  REQUIRE_FALSE(res.is_valid);
  REQUIRE(HasErrorCode(res, "MST_UNAUTHORIZED_RECEIPT"));
}

TEST_CASE("MST: embedded receipts raw fallback rejects non-bstr elements") {
  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};
  const auto stmt = EncodeStatementWithEmbeddedReceiptsArrayOfInts(statement_protected, statement_payload, statement_signature);

  cosesign1::mst::OfflineEcKeyStore store;
  cosesign1::mst::VerificationOptions opts;
  opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::VerifyAll;
  opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAnyMatching;

  const auto res = cosesign1::mst::VerifyTransparentStatement("Mst", stmt, store, opts);
  REQUIRE_FALSE(res.is_valid);
  REQUIRE(HasErrorCode(res, "MST_NO_RECEIPT"));
}

TEST_CASE("MST: inclusion leaf wrong type (int) yields MST_LEAF_PARSE_ERROR") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string issuer = "example.confidential-ledger.azure.com";
  const std::string kid = "kid";

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};
  const auto statement_no_unprotected = EncodeStatementNoUnprotected(statement_protected, statement_payload, statement_signature);
  const auto claims_digest = Sha256(statement_no_unprotected);

  const std::vector<std::uint8_t> internal_tx_hash(32, 0x11);
  const std::string evidence = "evidence";

  const auto inclusion_bad_leaf_type = EncodeInclusionMapLeafAndPathCustom(true,
                                                                           true,
                                                                           internal_tx_hash,
                                                                           evidence,
                                                                           claims_digest,
                                                                           [&](CborEncoder* map) {
                                                                             // path = []
                                                                             CborEncoder path;
                                                                             REQUIRE(cbor_encoder_create_array(map, &path, 0) == CborNoError);
                                                                             REQUIRE(cbor_encoder_close_container(map, &path) == CborNoError);
                                                                           });

  // Overwrite leaf value with an int by re-encoding a fresh map.
  std::vector<std::uint8_t> buf(512);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf.data(), buf.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, 2) != CborNoError) {
      buf.resize(buf.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 123) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 2) == CborNoError);
    // path = []
    CborEncoder path;
    REQUIRE(cbor_encoder_create_array(&map, &path, 0) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &path) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    buf.resize(cbor_encoder_get_buffer_size(&enc, buf.data()));
    break;
  }

  const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(buf);
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, std::vector<std::uint8_t>(64, 0x00));

  const auto jwk = MakeP256JwkFromKey(key.get(), kid);
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, statement_no_unprotected);
  REQUIRE_FALSE(res.is_valid);
  REQUIRE(HasErrorCode(res, "MST_LEAF_PARSE_ERROR"));
}

TEST_CASE("MST: inclusion path bytes invalid CBOR yields MST_PATH_PARSE_ERROR") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string issuer = "example.confidential-ledger.azure.com";
  const std::string kid = "kid";

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};
  const auto statement_no_unprotected = EncodeStatementNoUnprotected(statement_protected, statement_payload, statement_signature);
  const auto claims_digest = Sha256(statement_no_unprotected);

  const std::vector<std::uint8_t> internal_tx_hash(32, 0x11);
  const std::string evidence = "evidence";
  const auto leaf_bytes = EncodeLeafArrayBytes(internal_tx_hash, evidence, claims_digest);
  const std::vector<std::uint8_t> bad_path_bytes = {0xff};
  const auto inclusion_map_bytes = EncodeInclusionMapLeafAndPathAsBstr(leaf_bytes, bad_path_bytes);

  const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_map_bytes);
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, std::vector<std::uint8_t>(64, 0x00));

  const auto jwk = MakeP256JwkFromKey(key.get(), kid);
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, statement_no_unprotected);
  REQUIRE_FALSE(res.is_valid);
  REQUIRE(HasErrorCode(res, "MST_PATH_PARSE_ERROR"));
}

TEST_CASE("MST: VDP parse errors cover key/value shape checks") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string issuer = "example.confidential-ledger.azure.com";
  const std::string kid = "kid";

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};
  const auto statement_no_unprotected = EncodeStatementNoUnprotected(statement_protected, statement_payload, statement_signature);

  const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);

  // VDP map has a non-integer key => ReadInt64 fails.
  {
    const auto receipt_unprotected = EncodeReceiptUnprotectedVdpCustom([&](CborEncoder* out) {
      CborEncoder vdp;
      REQUIRE(cbor_encoder_create_map(out, &vdp, 1) == CborNoError);
      REQUIRE(cbor_encode_text_stringz(&vdp, "x") == CborNoError);
      REQUIRE(cbor_encode_int(&vdp, 1) == CborNoError);
      REQUIRE(cbor_encoder_close_container(out, &vdp) == CborNoError);
    });
    const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, std::vector<std::uint8_t>(64, 0x00));
    const auto jwk = MakeP256JwkFromKey(key.get(), kid);
    const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, statement_no_unprotected);
    REQUIRE_FALSE(res.is_valid);
    REQUIRE(HasErrorCode(res, "MST_VDP_PARSE_ERROR"));
  }

  // Inclusion label present but value is not an array.
  {
    const auto receipt_unprotected = EncodeReceiptUnprotectedVdpCustom([&](CborEncoder* out) {
      CborEncoder vdp;
      REQUIRE(cbor_encoder_create_map(out, &vdp, 1) == CborNoError);
      REQUIRE(cbor_encode_int(&vdp, -1) == CborNoError);
      REQUIRE(cbor_encode_int(&vdp, 1) == CborNoError);
      REQUIRE(cbor_encoder_close_container(out, &vdp) == CborNoError);
    });
    const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, std::vector<std::uint8_t>(64, 0x00));
    const auto jwk = MakeP256JwkFromKey(key.get(), kid);
    const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, statement_no_unprotected);
    REQUIRE_FALSE(res.is_valid);
    REQUIRE(HasErrorCode(res, "MST_INCLUSION_MISSING"));
  }

  // Inclusion array contains a non-byte-string element.
  {
    const auto receipt_unprotected = EncodeReceiptUnprotectedVdpCustom([&](CborEncoder* out) {
      CborEncoder vdp;
      REQUIRE(cbor_encoder_create_map(out, &vdp, 1) == CborNoError);
      REQUIRE(cbor_encode_int(&vdp, -1) == CborNoError);
      CborEncoder arr;
      REQUIRE(cbor_encoder_create_array(&vdp, &arr, 1) == CborNoError);
      REQUIRE(cbor_encode_int(&arr, 1) == CborNoError);
      REQUIRE(cbor_encoder_close_container(&vdp, &arr) == CborNoError);
      REQUIRE(cbor_encoder_close_container(out, &vdp) == CborNoError);
    });
    const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, std::vector<std::uint8_t>(64, 0x00));
    const auto jwk = MakeP256JwkFromKey(key.get(), kid);
    const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, statement_no_unprotected);
    REQUIRE_FALSE(res.is_valid);
    REQUIRE(HasErrorCode(res, "MST_INCLUSION_PARSE_ERROR"));
  }
}

TEST_CASE("MST: inclusion proof map key wrong type yields MST_INCLUSION_PARSE_ERROR") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string issuer = "example.confidential-ledger.azure.com";
  const std::string kid = "kid";

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};
  const auto statement_no_unprotected = EncodeStatementNoUnprotected(statement_protected, statement_payload, statement_signature);

  // inclusion map bytes: { "x": 1 }
  std::vector<std::uint8_t> inclusion_map_bytes(64);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, inclusion_map_bytes.data(), inclusion_map_bytes.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, 1) != CborNoError) {
      inclusion_map_bytes.resize(inclusion_map_bytes.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_text_stringz(&map, "x") == CborNoError);
    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    inclusion_map_bytes.resize(cbor_encoder_get_buffer_size(&enc, inclusion_map_bytes.data()));
    break;
  }

  const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_map_bytes);
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, std::vector<std::uint8_t>(64, 0x00));

  const auto jwk = MakeP256JwkFromKey(key.get(), kid);
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, statement_no_unprotected);
  REQUIRE_FALSE(res.is_valid);
  REQUIRE(HasErrorCode(res, "MST_INCLUSION_PARSE_ERROR"));
}

TEST_CASE("MST: VerifyTransparentStatementReceipt returns MST_JWK_ERROR on bad JWK") {
  cosesign1::mst::JwkEcPublicKey jwk;
  jwk.kty = "EC";
  jwk.crv = "P-256";
  jwk.kid = "kid";
  jwk.x_b64url = "!!!";
  jwk.y_b64url = "!!!";

  const std::vector<std::uint8_t> empty;
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, empty, empty);
  REQUIRE_FALSE(res.is_valid);
  REQUIRE(HasErrorCode(res, "MST_JWK_ERROR"));
}

TEST_CASE("MST: protected header size branches in detached signature wrapper") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string issuer = "example.confidential-ledger.azure.com";
  const std::string kid = "k";

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};
  const auto statement_no_unprotected = EncodeStatementNoUnprotected(statement_protected, statement_payload, statement_signature);
  const auto claims_digest = Sha256(statement_no_unprotected);

  const std::vector<std::uint8_t> internal_tx_hash(32, 0x11);
  const std::string evidence = "evidence";
  const auto inclusion_map_bytes = EncodeInclusionProofMapBytes(internal_tx_hash, evidence, claims_digest);

  const auto evidence_bytes = std::vector<std::uint8_t>(evidence.begin(), evidence.end());
  const auto evidence_hash = Sha256(evidence_bytes);
  std::vector<std::uint8_t> leaf_hash_input;
  leaf_hash_input.insert(leaf_hash_input.end(), internal_tx_hash.begin(), internal_tx_hash.end());
  leaf_hash_input.insert(leaf_hash_input.end(), evidence_hash.begin(), evidence_hash.end());
  leaf_hash_input.insert(leaf_hash_input.end(), claims_digest.begin(), claims_digest.end());
  const auto accumulator = Sha256(leaf_hash_input);

  const auto jwk = MakeP256JwkFromKey(key.get(), kid);

  // Small protected header (<24 bytes).
  {
    const auto receipt_protected = EncodeReceiptProtectedMinimalWithVdsAndPadding(-7, kid, 0);
    const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_map_bytes);
    const auto to_be_signed = BuildSigStructure(receipt_protected, accumulator);
    const auto receipt_signature = SignEs256ToCoseRaw(key.get(), to_be_signed);
    const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, receipt_signature);
    const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, statement_no_unprotected);
    INFO(DescribeFailures(res));
    REQUIRE(res.is_valid);
  }

  // Large protected header (> 65535 bytes) to exercise 4-byte CBOR length encoding.
  {
    const auto receipt_protected = EncodeReceiptProtectedMinimalWithVdsAndPadding(-7, kid, 70000);
    const auto receipt_unprotected = EncodeReceiptUnprotectedVdp(inclusion_map_bytes);
    const auto to_be_signed = BuildSigStructure(receipt_protected, accumulator);
    const auto receipt_signature = SignEs256ToCoseRaw(key.get(), to_be_signed);
    const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, receipt_signature);
    const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, statement_no_unprotected);
    INFO(DescribeFailures(res));
    REQUIRE(res.is_valid);
  }
}

TEST_CASE("MST: no authorized domains and IgnoreAll yields MST_NO_VERIFIABLE_RECEIPTS") {
  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};

  // Include one receipt so we get past MST_NO_RECEIPT.
  const auto receipt_protected = EncodeReceiptProtectedMissingIssuer(-7, "kid");
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdpWithRawInclusionArray(0, [](CborEncoder*) {});
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, std::vector<std::uint8_t>(64, 0x00));
  const auto statement = EncodeStatementWithEmbeddedReceipt(statement_protected, statement_payload, statement_signature, receipt);

  cosesign1::mst::OfflineEcKeyStore store;
  cosesign1::mst::VerificationOptions opts;
  opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::IgnoreAll;
  opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAnyMatching;

  const auto res = cosesign1::mst::VerifyTransparentStatement("Mst", statement, store, opts);
  REQUIRE_FALSE(res.is_valid);
  REQUIRE(HasErrorCode(res, "MST_NO_VERIFIABLE_RECEIPTS"));
}

TEST_CASE("MST: embedded receipts raw-CBOR fallback is exercised") {
  // Goal: ensure the verifier can parse an embedded receipts list encoded as an
  // indefinite-length array (forcing raw-value fallback), then proceed far enough
  // to emit a non-MST_NO_RECEIPT failure.

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};

  const std::string kid = "kid";
  const auto receipt_protected = EncodeReceiptProtectedMissingIssuer(-7, kid);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdpWithRawInclusionArray(0, [](CborEncoder*) {});
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, std::vector<std::uint8_t>(64, 0x00));

  const auto transparent_statement = EncodeStatementWithEmbeddedReceiptsIndefiniteArray(statement_protected,
                                                                                        statement_payload,
                                                                                        statement_signature,
                                                                                        {receipt});

  cosesign1::mst::OfflineEcKeyStore store;
  cosesign1::mst::VerificationOptions opts;
  opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::VerifyAll;
  opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAnyMatching;

  const auto res = cosesign1::mst::VerifyTransparentStatement("Mst", transparent_statement, store, opts);
  REQUIRE_FALSE(res.is_valid);
  INFO(DescribeFailures(res));
  REQUIRE(HasErrorCode(res, "MST_UNKNOWN_ISSUER"));
}

TEST_CASE("MST: embedded receipts wrong type triggers MST_NO_RECEIPT") {
  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};

  const auto transparent_statement = EncodeStatementWithEmbeddedReceiptsWrongType(statement_protected,
                                                                                  statement_payload,
                                                                                  statement_signature);

  cosesign1::mst::OfflineEcKeyStore store;
  cosesign1::mst::VerificationOptions opts;
  opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::VerifyAll;
  opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAnyMatching;

  const auto res = cosesign1::mst::VerifyTransparentStatement("Mst", transparent_statement, store, opts);
  REQUIRE_FALSE(res.is_valid);
  INFO(DescribeFailures(res));
  REQUIRE(HasErrorCode(res, "MST_NO_RECEIPT"));
}

TEST_CASE("MST: invalid embedded receipt is treated as unknown issuer") {
  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};

  // Receipt bytes are a bstr, but the contents are not a COSE_Sign1 CBOR structure.
  const std::vector<std::uint8_t> invalid_receipt = {0x01, 0x02, 0x03};
  const auto transparent_statement =
      EncodeStatementWithEmbeddedReceipts(statement_protected, statement_payload, statement_signature, {invalid_receipt});

  cosesign1::mst::OfflineEcKeyStore store;
  cosesign1::mst::VerificationOptions opts;
  opts.authorized_domains = {"example.confidential-ledger.azure.com"};
  opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::VerifyAll;
  opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAnyMatching;

  const auto res = cosesign1::mst::VerifyTransparentStatement("Mst", transparent_statement, store, opts);
  REQUIRE_FALSE(res.is_valid);
  INFO(DescribeFailures(res));
  REQUIRE(HasErrorCode(res, "MST_UNKNOWN_ISSUER"));
  REQUIRE(HasErrorCode(res, "MST_NO_VALID_AUTHORIZED_RECEIPTS"));
}

TEST_CASE("MST: KID wrong type forces raw fallback and yields MST_KID_MISSING") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string issuer = "example.confidential-ledger.azure.com";
  const std::vector<std::uint8_t> claims = {'c','l','a','i','m','s'};

  const auto claims_digest = Sha256(claims);
  const auto inclusion_map_bytes = EncodeInclusionProofMapBytes(std::vector<std::uint8_t>(32, 0x11), "evidence", claims_digest);
  const auto receipt_protected = EncodeReceiptProtectedKidWrongType(-7, "kid-as-text", issuer);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdpWithExtraKey(inclusion_map_bytes);
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, std::vector<std::uint8_t>(64, 0x00));

  const auto jwk = MakeP256JwkFromKey(key.get(), "kid");
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, claims);
  REQUIRE_FALSE(res.is_valid);
  INFO(DescribeFailures(res));
  REQUIRE(HasErrorCode(res, "MST_KID_MISSING"));
}

TEST_CASE("MST: VDS wrong type forces raw fallback and yields MST_VDS_MISSING") {
  auto key = GenerateEcP256Key();
  REQUIRE(key);

  const std::string issuer = "example.confidential-ledger.azure.com";
  const std::string kid = "kid";
  const std::vector<std::uint8_t> claims = {'c','l','a','i','m','s'};

  const auto claims_digest = Sha256(claims);
  const auto inclusion_map_bytes = EncodeInclusionProofMapBytes(std::vector<std::uint8_t>(32, 0x11), "evidence", claims_digest);
  const auto receipt_protected = EncodeReceiptProtectedVdsWrongType(-7, kid, issuer);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdpWithExtraKey(inclusion_map_bytes);
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, std::vector<std::uint8_t>(64, 0x00));

  const auto jwk = MakeP256JwkFromKey(key.get(), kid);
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, claims);
  REQUIRE_FALSE(res.is_valid);
  INFO(DescribeFailures(res));
  REQUIRE(HasErrorCode(res, "MST_VDS_MISSING"));
}

TEST_CASE("MST: VDP SkipAny path is exercised with extra VDP keys") {
  // Build a receipt that gets as far as signature verification, but fails there.
  auto key = GenerateEcP256Key();
  REQUIRE(key);
  const std::string issuer = "example.confidential-ledger.azure.com";
  const std::string kid = "kid";

  const std::vector<std::uint8_t> claims = {'c','l','a','i','m','s'};
  const auto claims_digest = Sha256(claims);

  const std::vector<std::uint8_t> internal_tx_hash(32, 0x11);
  const std::string evidence = "evidence";
  const auto inclusion_map_bytes = EncodeInclusionProofMapBytes(internal_tx_hash, evidence, claims_digest);

  const auto receipt_protected = EncodeReceiptProtected(-7, kid, issuer);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdpWithExtraKey(inclusion_map_bytes);
  const auto receipt = EncodeCoseSign1(receipt_protected, receipt_unprotected, true, {}, std::vector<std::uint8_t>(64, 0x00));

  const auto jwk = MakeP256JwkFromKey(key.get(), kid);
  const auto res = cosesign1::mst::VerifyTransparentStatementReceipt("MstReceipt", jwk, receipt, claims);
  REQUIRE_FALSE(res.is_valid);
  INFO(DescribeFailures(res));
  REQUIRE(HasErrorCode(res, "MST_RECEIPT_SIGNATURE_INVALID"));
}

TEST_CASE("MST: NormalizeKid hex path appears in key-not-found message") {
  // KID bytes contain NUL -> not printable ASCII, so verifier should hex-normalize.
  const std::vector<std::uint8_t> kid_bytes = {'k', 0x00, 'd'};
  const std::string issuer = "example.confidential-ledger.azure.com";

  // protected headers (kid as bstr with embedded NUL, issuer present, vds=CCF)
  std::vector<std::uint8_t> protected_hdr(512);
  while (true) {
    CborEncoder enc;
    cbor_encoder_init(&enc, protected_hdr.data(), protected_hdr.size(), 0);
    CborEncoder map;
    if (cbor_encoder_create_map(&enc, &map, CborIndefiniteLength) != CborNoError) {
      protected_hdr.resize(protected_hdr.size() * 2);
      continue;
    }
    REQUIRE(cbor_encode_int(&map, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&map, -7) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 4) == CborNoError);
    REQUIRE(cbor_encode_byte_string(&map, kid_bytes.data(), kid_bytes.size()) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 395) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 2) == CborNoError);
    REQUIRE(cbor_encode_int(&map, 15) == CborNoError);
    CborEncoder cwt;
    REQUIRE(cbor_encoder_create_map(&map, &cwt, 1) == CborNoError);
    REQUIRE(cbor_encode_int(&cwt, 1) == CborNoError);
    REQUIRE(cbor_encode_text_string(&cwt, issuer.data(), issuer.size()) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&map, &cwt) == CborNoError);
    REQUIRE(cbor_encoder_close_container(&enc, &map) == CborNoError);
    protected_hdr.resize(cbor_encoder_get_buffer_size(&enc, protected_hdr.data()));
    break;
  }

  const std::vector<std::uint8_t> claims = {'c','l','a','i','m','s'};
  const auto claims_digest = Sha256(claims);
  const auto inclusion_map_bytes = EncodeInclusionProofMapBytes(std::vector<std::uint8_t>(32, 0x11), "evidence", claims_digest);
  const auto receipt_unprotected = EncodeReceiptUnprotectedVdpWithExtraKey(inclusion_map_bytes);
  const auto receipt = EncodeCoseSign1(protected_hdr, receipt_unprotected, true, {}, std::vector<std::uint8_t>(64, 0x00));

  const auto statement_protected = EncodeMapAlgOnly(-7);
  const std::vector<std::uint8_t> statement_payload = {'p','a','y'};
  const std::vector<std::uint8_t> statement_signature = {0x01, 0x02};
  const auto transparent_statement = EncodeStatementWithEmbeddedReceipt(statement_protected, statement_payload, statement_signature, receipt);

  cosesign1::mst::OfflineEcKeyStore store;
  cosesign1::mst::VerificationOptions opts;
  opts.unauthorized_receipt_behavior = cosesign1::mst::UnauthorizedReceiptBehavior::VerifyAll;
  opts.authorized_receipt_behavior = cosesign1::mst::AuthorizedReceiptBehavior::VerifyAnyMatching;

  const auto res = cosesign1::mst::VerifyTransparentStatement("Mst", transparent_statement, store, opts);
  REQUIRE_FALSE(res.is_valid);
  INFO(DescribeFailures(res));
  REQUIRE(HasErrorCode(res, "MST_KEY_NOT_FOUND"));

  const std::string failures = DescribeFailures(res);
  REQUIRE(failures.find("6b0064") != std::string::npos);
}
