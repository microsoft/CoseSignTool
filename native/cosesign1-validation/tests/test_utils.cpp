// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/**
 * @file test_utils.cpp
 * @brief Test helper implementations.
 */

#include "test_utils.h"

#include <functional>
#include <stdexcept>

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#if defined(COSESIGN1_ENABLE_PQC)
#include <oqs/oqs.h>
#endif

#include "../src/internal/openssl_utils.h"

namespace cosesign1::tests {

namespace {
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

BioPtr MakeMemBio() {
  return BioPtr(BIO_new(BIO_s_mem()), &BIO_free);
}

std::vector<std::uint8_t> ReadAllFromBio(BIO* bio) {
  BUF_MEM* mem = nullptr;
  BIO_get_mem_ptr(bio, &mem);
  if (!mem || !mem->data || mem->length == 0) {
    return {};
  }
  const auto* p = reinterpret_cast<const std::uint8_t*>(mem->data);
  return std::vector<std::uint8_t>(p, p + mem->length);
}

std::vector<std::uint8_t> DigestSign(EVP_PKEY* key,
                                     const EVP_MD* md,
                                     std::span<const std::uint8_t> data,
                                     const std::function<bool(EVP_PKEY_CTX*)>& configure) {
  MdCtxPtr ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
  if (!ctx) throw std::runtime_error("EVP_MD_CTX_new failed");

  EVP_PKEY_CTX* pctx = nullptr;
  if (EVP_DigestSignInit(ctx.get(), &pctx, md, nullptr, key) != 1) {
    throw std::runtime_error("EVP_DigestSignInit failed");
  }

  if (configure && !configure(pctx)) {
    throw std::runtime_error("configure failed");
  }

  if (EVP_DigestSignUpdate(ctx.get(), data.data(), data.size()) != 1) {
    throw std::runtime_error("EVP_DigestSignUpdate failed");
  }

  std::size_t sig_len = 0;
  if (EVP_DigestSignFinal(ctx.get(), nullptr, &sig_len) != 1) {
    throw std::runtime_error("EVP_DigestSignFinal(size) failed");
  }

  std::vector<std::uint8_t> sig(sig_len);
  if (EVP_DigestSignFinal(ctx.get(), sig.data(), &sig_len) != 1) {
    throw std::runtime_error("EVP_DigestSignFinal failed");
  }
  sig.resize(sig_len);
  return sig;
}

std::vector<std::uint8_t> EncodeBytesOrResize(const std::function<CborError(std::uint8_t*, size_t, size_t&)>& encode) {
  std::vector<std::uint8_t> buf(512);
  while (true) {
    size_t used = 0;
    auto err = encode(buf.data(), buf.size(), used);
    if (err == CborErrorOutOfMemory) {
      buf.resize(buf.size() * 2);
      continue;
    }
    if (err != CborNoError) {
      throw std::runtime_error("CBOR encode failed");
    }
    buf.resize(used);
    return buf;
  }
}

} // namespace

std::string PublicKeyPemFromKey(EVP_PKEY* key) {
  auto bio = MakeMemBio();
  if (!bio) throw std::runtime_error("BIO_new failed");

  if (PEM_write_bio_PUBKEY(bio.get(), key) != 1) {
    throw std::runtime_error("PEM_write_bio_PUBKEY failed");
  }

  auto bytes = ReadAllFromBio(bio.get());
  return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::vector<std::uint8_t> PublicKeyDerFromKey(EVP_PKEY* key) {
  const int len = i2d_PUBKEY(key, nullptr);
  if (len <= 0) {
    throw std::runtime_error("i2d_PUBKEY failed");
  }

  std::vector<std::uint8_t> out(static_cast<std::size_t>(len));
  unsigned char* p = out.data();
  if (i2d_PUBKEY(key, &p) != len) {
    throw std::runtime_error("i2d_PUBKEY wrote unexpected length");
  }
  return out;
}

std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> GenerateEcP256Key() {
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  if (!pctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(pctx, &EVP_PKEY_CTX_free);

  if (EVP_PKEY_keygen_init(ctx.get()) != 1) throw std::runtime_error("EVP_PKEY_keygen_init failed");
  if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx.get(), NID_X9_62_prime256v1) != 1) {
    throw std::runtime_error("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed");
  }

  EVP_PKEY* key = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &key) != 1) throw std::runtime_error("EVP_PKEY_keygen failed");
  return std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(key, &EVP_PKEY_free);
}

std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)> GenerateRsaKey(int bits) {
  EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  if (!pctx) throw std::runtime_error("EVP_PKEY_CTX_new_id failed");

  std::unique_ptr<EVP_PKEY_CTX, decltype(&EVP_PKEY_CTX_free)> ctx(pctx, &EVP_PKEY_CTX_free);

  if (EVP_PKEY_keygen_init(ctx.get()) != 1) throw std::runtime_error("EVP_PKEY_keygen_init failed");
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx.get(), bits) != 1) throw std::runtime_error("EVP_PKEY_CTX_set_rsa_keygen_bits failed");

  EVP_PKEY* key = nullptr;
  if (EVP_PKEY_keygen(ctx.get(), &key) != 1) throw std::runtime_error("EVP_PKEY_keygen failed");
  return std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>(key, &EVP_PKEY_free);
}

std::vector<std::uint8_t> MakeProtectedHeaderAlg(std::int64_t alg) {
  // Encoded header map: { 1: alg }
  return EncodeBytesOrResize([&](std::uint8_t* buf, size_t cap, size_t& used) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf, cap, 0);

    CborEncoder map;
    CborError err = cbor_encoder_create_map(&enc, &map, 1);
    if (err != CborNoError) return err;

    err = cbor_encode_int(&map, 1);
    if (err != CborNoError) return err;

    err = cbor_encode_int(&map, alg);
    if (err != CborNoError) return err;

    err = cbor_encoder_close_container(&enc, &map);
    if (err != CborNoError) return err;

    used = cbor_encoder_get_buffer_size(&enc, buf);
    return CborNoError;
  });
}

std::vector<std::uint8_t> BuildSigStructure(const std::vector<std::uint8_t>& protected_header_bstr,
                                            std::span<const std::uint8_t> payload) {
  // Sig_structure = ["Signature1", body_protected, external_aad, payload]
  return EncodeBytesOrResize([&](std::uint8_t* buf, size_t cap, size_t& used) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf, cap, 0);

    CborEncoder arr;
    CborError err = cbor_encoder_create_array(&enc, &arr, 4);
    if (err != CborNoError) return err;

    err = cbor_encode_text_stringz(&arr, "Signature1");
    if (err != CborNoError) return err;

    err = cbor_encode_byte_string(&arr, protected_header_bstr.data(), protected_header_bstr.size());
    if (err != CborNoError) return err;

    err = cbor_encode_byte_string(&arr, nullptr, 0);
    if (err != CborNoError) return err;

    err = cbor_encode_byte_string(&arr, payload.data(), payload.size());
    if (err != CborNoError) return err;

    err = cbor_encoder_close_container(&enc, &arr);
    if (err != CborNoError) return err;

    used = cbor_encoder_get_buffer_size(&enc, buf);
    return CborNoError;
  });
}

std::vector<std::uint8_t> MakeCoseSign1(const std::vector<std::uint8_t>& protected_header_bstr,
                                        bool payload_is_detached,
                                        std::span<const std::uint8_t> payload,
                                        std::span<const std::uint8_t> signature) {
  // COSE_Sign1 = [protected: bstr, unprotected: map, payload: bstr/null, signature: bstr]
  return EncodeBytesOrResize([&](std::uint8_t* buf, size_t cap, size_t& used) {
    CborEncoder enc;
    cbor_encoder_init(&enc, buf, cap, 0);

    CborEncoder arr;
    CborError err = cbor_encoder_create_array(&enc, &arr, 4);
    if (err != CborNoError) return err;

    err = cbor_encode_byte_string(&arr, protected_header_bstr.data(), protected_header_bstr.size());
    if (err != CborNoError) return err;

    CborEncoder map;
    err = cbor_encoder_create_map(&arr, &map, 0);
    if (err != CborNoError) return err;

    err = cbor_encoder_close_container(&arr, &map);
    if (err != CborNoError) return err;

    if (payload_is_detached) {
      err = cbor_encode_null(&arr);
    } else {
      err = cbor_encode_byte_string(&arr, payload.data(), payload.size());
    }
    if (err != CborNoError) return err;

    err = cbor_encode_byte_string(&arr, signature.data(), signature.size());
    if (err != CborNoError) return err;

    err = cbor_encoder_close_container(&enc, &arr);
    if (err != CborNoError) return err;

    used = cbor_encoder_get_buffer_size(&enc, buf);
    return CborNoError;
  });
}

std::vector<std::uint8_t> SignEs256ToCoseRaw(EVP_PKEY* key, std::span<const std::uint8_t> to_be_signed) {
  auto der = DigestSign(key, EVP_sha256(), to_be_signed, [](EVP_PKEY_CTX*) { return true; });
  auto raw = cosesign1::internal::EcdsaDerToCoseRaw(der, 32);
  if (!raw) throw std::runtime_error("EcdsaDerToCoseRaw failed");
  return *raw;
}

std::vector<std::uint8_t> SignPs256(EVP_PKEY* key, std::span<const std::uint8_t> to_be_signed) {
  return DigestSign(key, EVP_sha256(), to_be_signed, [](EVP_PKEY_CTX* pctx) {
    if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1) return false;
    if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) != 1) return false;
    if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) != 1) return false;
    return true;
  });
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
    case -49:
#if defined(OQS_SIG_alg_ml_dsa_65)
      return OQS_SIG_alg_ml_dsa_65;
#else
      return OQS_SIG_alg_dilithium_3;
#endif
    case -50:
#if defined(OQS_SIG_alg_ml_dsa_87)
      return OQS_SIG_alg_ml_dsa_87;
#else
      return OQS_SIG_alg_dilithium_5;
#endif
    default:
      return nullptr;
  }
}
} // namespace

OqsKeyPair GenerateMlDsaKeyPair(std::int64_t cose_alg) {
  const char* alg = OqsAlgFromCoseAlg(cose_alg);
  if (!alg) throw std::runtime_error("unsupported ML-DSA cose alg");

  std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> sig(OQS_SIG_new(alg), &OQS_SIG_free);
  if (!sig) throw std::runtime_error("OQS_SIG_new failed");

  OqsKeyPair kp;
  kp.public_key.resize(sig->length_public_key);
  kp.secret_key.resize(sig->length_secret_key);

  if (OQS_SIG_keypair(sig.get(), kp.public_key.data(), kp.secret_key.data()) != OQS_SUCCESS) {
    throw std::runtime_error("OQS_SIG_keypair failed");
  }
  return kp;
}

std::vector<std::uint8_t> SignMlDsa(std::int64_t cose_alg,
                                    std::span<const std::uint8_t> to_be_signed,
                                    std::span<const std::uint8_t> secret_key) {
  const char* alg = OqsAlgFromCoseAlg(cose_alg);
  if (!alg) throw std::runtime_error("unsupported ML-DSA cose alg");

  std::unique_ptr<OQS_SIG, decltype(&OQS_SIG_free)> sig(OQS_SIG_new(alg), &OQS_SIG_free);
  if (!sig) throw std::runtime_error("OQS_SIG_new failed");

  if (secret_key.size() != sig->length_secret_key) {
    throw std::runtime_error("secret key length mismatch");
  }

  std::vector<std::uint8_t> signature(sig->length_signature);
  std::size_t sig_len = signature.size();
  if (OQS_SIG_sign(sig.get(),
                   signature.data(),
                   &sig_len,
                   to_be_signed.data(),
                   to_be_signed.size(),
                   secret_key.data()) != OQS_SUCCESS) {
    throw std::runtime_error("OQS_SIG_sign failed");
  }
  signature.resize(sig_len);
  return signature;
}
#endif

} // namespace cosesign1::tests
