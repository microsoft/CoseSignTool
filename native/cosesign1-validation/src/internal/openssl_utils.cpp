#include "openssl_utils.h"

#include <cstring>

#include <openssl/bio.h>
#include <openssl/ecdsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

namespace cosesign1::internal {

namespace {
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using MdCtxPtr = std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)>;

BioPtr MakeBioFromString(const std::string& s) {
  BIO* b = BIO_new_mem_buf(s.data(), static_cast<int>(s.size()));
  return BioPtr(b, &BIO_free);
}

} // namespace

EvpPkeyPtr LoadPublicKeyOrCertFromPem(const std::string& pem) {
  auto bio = MakeBioFromString(pem);
  if (!bio) {
    return EvpPkeyPtr(nullptr, &EVP_PKEY_free);
  }

  // Try public key first.
  if (EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio.get(), nullptr, nullptr, nullptr)) {
    return EvpPkeyPtr(pkey, &EVP_PKEY_free);
  }

  // Reset and try certificate.
  bio = MakeBioFromString(pem);
  if (X509* cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr)) {
    EVP_PKEY* pkey = X509_get_pubkey(cert);
    X509_free(cert);
    return EvpPkeyPtr(pkey, &EVP_PKEY_free);
  }

  return EvpPkeyPtr(nullptr, &EVP_PKEY_free);
}

EvpPkeyPtr LoadPublicKeyOrCertFromDer(std::span<const std::uint8_t> der) {
  if (der.empty()) {
    return EvpPkeyPtr(nullptr, &EVP_PKEY_free);
  }

  const unsigned char* p = der.data();
  const unsigned char* end = der.data() + der.size();
  // Try SubjectPublicKeyInfo first.
  if (EVP_PKEY* pkey = d2i_PUBKEY(nullptr, &p, static_cast<long>(der.size()))) {
    // Only accept if the parser consumed the entire buffer.
    if (p == end) {
      return EvpPkeyPtr(pkey, &EVP_PKEY_free);
    }
    EVP_PKEY_free(pkey);
  }

  // Reset pointer and try X.509 certificate.
  p = der.data();
  if (X509* cert = d2i_X509(nullptr, &p, static_cast<long>(der.size()))) {
    // Only accept if the parser consumed the entire buffer.
    if (p == end) {
      EVP_PKEY* pkey = X509_get_pubkey(cert);
      X509_free(cert);
      return EvpPkeyPtr(pkey, &EVP_PKEY_free);
    }
    X509_free(cert);
  }

  return EvpPkeyPtr(nullptr, &EVP_PKEY_free);
}

std::optional<std::vector<std::uint8_t>> ExtractSubjectPublicKeyBytesFromCertificatePem(const std::string& pem) {
  auto bio = MakeBioFromString(pem);
  if (!bio) {
    return std::nullopt;
  }

  X509* cert = PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr);
  if (!cert) {
    return std::nullopt;
  }

  const ASN1_BIT_STRING* pk = X509_get0_pubkey_bitstr(cert);
  if (!pk || !pk->data || pk->length <= 0) {
    X509_free(cert);
    return std::nullopt;
  }

  std::vector<std::uint8_t> out(pk->data, pk->data + pk->length);
  X509_free(cert);
  return out;
}

std::optional<std::vector<std::uint8_t>> CoseEcdsaRawToDer(std::span<const std::uint8_t> cose_raw_sig) {
  if (cose_raw_sig.size() % 2 != 0 || cose_raw_sig.empty()) {
    return std::nullopt;
  }

  const std::size_t n = cose_raw_sig.size() / 2;
  const std::uint8_t* r_bytes = cose_raw_sig.data();
  const std::uint8_t* s_bytes = cose_raw_sig.data() + n;

  BIGNUM* r = BN_bin2bn(r_bytes, static_cast<int>(n), nullptr);
  BIGNUM* s = BN_bin2bn(s_bytes, static_cast<int>(n), nullptr);
  if (!r || !s) {
    if (r) BN_free(r);
    if (s) BN_free(s);
    return std::nullopt;
  }

  ECDSA_SIG* sig = ECDSA_SIG_new();
  if (!sig) {
    BN_free(r);
    BN_free(s);
    return std::nullopt;
  }

  if (ECDSA_SIG_set0(sig, r, s) != 1) {
    ECDSA_SIG_free(sig);
    BN_free(r);
    BN_free(s);
    return std::nullopt;
  }

  int len = i2d_ECDSA_SIG(sig, nullptr);
  if (len <= 0) {
    ECDSA_SIG_free(sig);
    return std::nullopt;
  }

  std::vector<std::uint8_t> der(static_cast<std::size_t>(len));
  unsigned char* out = der.data();
  if (i2d_ECDSA_SIG(sig, &out) != len) {
    ECDSA_SIG_free(sig);
    return std::nullopt;
  }

  ECDSA_SIG_free(sig);
  return der;
}

std::optional<std::vector<std::uint8_t>> EcdsaDerToCoseRaw(std::span<const std::uint8_t> der_sig, std::size_t component_size) {
  const unsigned char* p = der_sig.data();
  ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der_sig.size()));
  if (!sig) {
    return std::nullopt;
  }

  const BIGNUM* r = nullptr;
  const BIGNUM* s = nullptr;
  ECDSA_SIG_get0(sig, &r, &s);

  std::vector<std::uint8_t> raw(component_size * 2);
  if (BN_bn2binpad(r, raw.data(), static_cast<int>(component_size)) != static_cast<int>(component_size) ||
      BN_bn2binpad(s, raw.data() + component_size, static_cast<int>(component_size)) != static_cast<int>(component_size)) {
    ECDSA_SIG_free(sig);
    return std::nullopt;
  }

  ECDSA_SIG_free(sig);
  return raw;
}

bool VerifyEs256(EVP_PKEY* key, std::span<const std::uint8_t> to_be_signed, std::span<const std::uint8_t> cose_raw_sig) {
  auto der = CoseEcdsaRawToDer(cose_raw_sig);
  if (!der) {
    return false;
  }

  MdCtxPtr ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
  if (!ctx) return false;

  if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key) != 1) return false;
  if (EVP_DigestVerifyUpdate(ctx.get(), to_be_signed.data(), to_be_signed.size()) != 1) return false;

  const int ok = EVP_DigestVerifyFinal(ctx.get(), der->data(), der->size());
  return ok == 1;
}

bool VerifyEs384(EVP_PKEY* key, std::span<const std::uint8_t> to_be_signed, std::span<const std::uint8_t> cose_raw_sig) {
  auto der = CoseEcdsaRawToDer(cose_raw_sig);
  if (!der) {
    return false;
  }

  MdCtxPtr ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
  if (!ctx) return false;

  if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha384(), nullptr, key) != 1) return false;
  if (EVP_DigestVerifyUpdate(ctx.get(), to_be_signed.data(), to_be_signed.size()) != 1) return false;
  return EVP_DigestVerifyFinal(ctx.get(), der->data(), der->size()) == 1;
}

bool VerifyEs512(EVP_PKEY* key, std::span<const std::uint8_t> to_be_signed, std::span<const std::uint8_t> cose_raw_sig) {
  auto der = CoseEcdsaRawToDer(cose_raw_sig);
  if (!der) {
    return false;
  }

  MdCtxPtr ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
  if (!ctx) return false;

  if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha512(), nullptr, key) != 1) return false;
  if (EVP_DigestVerifyUpdate(ctx.get(), to_be_signed.data(), to_be_signed.size()) != 1) return false;
  return EVP_DigestVerifyFinal(ctx.get(), der->data(), der->size()) == 1;
}

bool VerifyPs256(EVP_PKEY* key, std::span<const std::uint8_t> to_be_signed, std::span<const std::uint8_t> signature) {
  MdCtxPtr ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
  if (!ctx) return false;

  EVP_PKEY_CTX* pctx = nullptr;
  if (EVP_DigestVerifyInit(ctx.get(), &pctx, EVP_sha256(), nullptr, key) != 1) return false;
  if (EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PSS_PADDING) != 1) return false;
  if (EVP_PKEY_CTX_set_rsa_mgf1_md(pctx, EVP_sha256()) != 1) return false;
  if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pctx, -1) != 1) return false;

  if (EVP_DigestVerifyUpdate(ctx.get(), to_be_signed.data(), to_be_signed.size()) != 1) return false;
  return EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size()) == 1;
}

bool VerifyRs256(EVP_PKEY* key, std::span<const std::uint8_t> to_be_signed, std::span<const std::uint8_t> signature) {
  MdCtxPtr ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
  if (!ctx) return false;

  if (EVP_DigestVerifyInit(ctx.get(), nullptr, EVP_sha256(), nullptr, key) != 1) return false;
  if (EVP_DigestVerifyUpdate(ctx.get(), to_be_signed.data(), to_be_signed.size()) != 1) return false;
  return EVP_DigestVerifyFinal(ctx.get(), signature.data(), signature.size()) == 1;
}

} // namespace cosesign1::internal
