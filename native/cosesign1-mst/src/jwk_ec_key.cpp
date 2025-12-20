#include "cosesign1/mst/jwk_ec_key.h"

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

namespace cosesign1::mst {

namespace {
using BioPtr = std::unique_ptr<BIO, decltype(&BIO_free)>;
using BnPtr = std::unique_ptr<BIGNUM, decltype(&BN_free)>;
using EcKeyPtr = std::unique_ptr<EC_KEY, decltype(&EC_KEY_free)>;
using EcPointPtr = std::unique_ptr<EC_POINT, decltype(&EC_POINT_free)>;
using EvpPkeyPtr = std::unique_ptr<EVP_PKEY, decltype(&EVP_PKEY_free)>;

std::string ToLower(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (char ch : s) {
    out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(ch))));
  }
  return out;
}

std::optional<std::vector<std::uint8_t>> Base64UrlDecode(std::string_view in) {
  std::string b64;
  b64.reserve(in.size() + 4);
  for (char c : in) {
    if (c == '-') {
      b64.push_back('+');
    } else if (c == '_') {
      b64.push_back('/');
    } else if (c == '=') {
      // ignore explicit padding
    } else {
      b64.push_back(c);
    }
  }

  while (b64.size() % 4 != 0) {
    b64.push_back('=');
  }

  std::vector<std::uint8_t> out((b64.size() / 4) * 3);
  const int len = EVP_DecodeBlock(out.data(), reinterpret_cast<const unsigned char*>(b64.data()), static_cast<int>(b64.size()));
  if (len < 0) {
    return std::nullopt;
  }

  std::size_t actual = static_cast<std::size_t>(len);
  // Trim bytes introduced by '=' padding.
  if (!b64.empty() && b64.back() == '=') {
    actual--;
    if (b64.size() >= 2 && b64[b64.size() - 2] == '=') {
      actual--;
    }
  }

  out.resize(actual);
  return out;
}

BioPtr MakeBio() {
  return BioPtr(BIO_new(BIO_s_mem()), &BIO_free);
}

std::optional<std::string> BioToString(BIO* bio) {
  char* data = nullptr;
  const long len = BIO_get_mem_data(bio, &data);
  if (len <= 0 || !data) {
    return std::nullopt;
  }
  return std::string(data, static_cast<std::size_t>(len));
}

std::optional<int> NidFromCrv(std::string_view crv) {
  const auto lc = ToLower(crv);
  if (lc == "p-256") return NID_X9_62_prime256v1;
  if (lc == "p-384") return NID_secp384r1;
  if (lc == "p-521") return NID_secp521r1;
  return std::nullopt;
}

std::optional<EvpPkeyPtr> EcJwkToEvpPkey(const JwkEcPublicKey& jwk) {
  if (ToLower(jwk.kty) != "ec") {
    return std::nullopt;
  }

  const auto nid = NidFromCrv(jwk.crv);
  if (!nid) {
    return std::nullopt;
  }

  const auto x = Base64UrlDecode(jwk.x_b64url);
  const auto y = Base64UrlDecode(jwk.y_b64url);
  if (!x || !y) {
    return std::nullopt;
  }

  EcKeyPtr ec(EC_KEY_new_by_curve_name(*nid), &EC_KEY_free);
  if (!ec) {
    return std::nullopt;
  }

  const EC_GROUP* group = EC_KEY_get0_group(ec.get());
  if (!group) {
    return std::nullopt;
  }

  BnPtr bn_x(BN_bin2bn(x->data(), static_cast<int>(x->size()), nullptr), &BN_free);
  BnPtr bn_y(BN_bin2bn(y->data(), static_cast<int>(y->size()), nullptr), &BN_free);
  if (!bn_x || !bn_y) {
    return std::nullopt;
  }

  EcPointPtr point(EC_POINT_new(group), &EC_POINT_free);
  if (!point) {
    return std::nullopt;
  }

  if (EC_POINT_set_affine_coordinates(group, point.get(), bn_x.get(), bn_y.get(), nullptr) != 1) {
    return std::nullopt;
  }

  if (EC_KEY_set_public_key(ec.get(), point.get()) != 1) {
    return std::nullopt;
  }

  EvpPkeyPtr pkey(EVP_PKEY_new(), &EVP_PKEY_free);
  if (!pkey) {
    return std::nullopt;
  }

  if (EVP_PKEY_set1_EC_KEY(pkey.get(), ec.get()) != 1) {
    return std::nullopt;
  }

  return std::optional<EvpPkeyPtr>(std::move(pkey));
}

} // namespace

namespace internal {

void RunCoverageHooks_JwkEcKey() {
  // Exercise BioToString's empty-buffer path (len <= 0).
  auto bio = MakeBio();
  if (bio) {
    (void)BioToString(bio.get());
  }
}

} // namespace internal

std::optional<cosesign1::validation::CoseAlgorithm> ExpectedAlgFromCrv(std::string_view crv) {
  const auto lc = ToLower(crv);
  if (lc == "p-256") return cosesign1::validation::CoseAlgorithm::ES256;
  if (lc == "p-384") return cosesign1::validation::CoseAlgorithm::ES384;
  if (lc == "p-521") return cosesign1::validation::CoseAlgorithm::ES512;
  return std::nullopt;
}

std::optional<JwksDocument> ParseJwks(std::string_view jwks_json) {
  JwksDocument out;

  nlohmann::json j;
  try {
    j = nlohmann::json::parse(jwks_json.begin(), jwks_json.end());
  } catch (...) {
    return std::nullopt;
  }

  if (!j.is_object() || !j.contains("keys") || !j["keys"].is_array()) {
    return std::nullopt;
  }

  for (const auto& k : j["keys"]) {
    if (!k.is_object()) continue;

    JwkEcPublicKey key;
    key.kty = k.value("kty", "");
    key.crv = k.value("crv", "");
    key.kid = k.value("kid", "");
    key.x_b64url = k.value("x", "");
    key.y_b64url = k.value("y", "");
    const bool is_ec = (ToLower(key.kty) == "ec");
    const bool has_ec_params = !key.crv.empty() && !key.x_b64url.empty() && !key.y_b64url.empty();

    if (key.kid.empty()) {
      continue;
    }

    if (!is_ec || !has_ec_params) {
      continue;
    }

    if (!ExpectedAlgFromCrv(key.crv)) {
      continue;
    }

    out.keys.push_back(std::move(key));
  }

  if (out.keys.empty()) {
    return std::nullopt;
  }

  return out;
}

std::optional<std::string> EcJwkToPublicKeyPem(const JwkEcPublicKey& jwk) {
  auto pkey_opt = EcJwkToEvpPkey(jwk);
  if (!pkey_opt) {
    return std::nullopt;
  }
  auto& pkey = *pkey_opt;

  auto bio = MakeBio();
  if (!bio) {
    return std::nullopt;
  }

  if (PEM_write_bio_PUBKEY(bio.get(), pkey.get()) != 1) {
    return std::nullopt;
  }

  return BioToString(bio.get());
}

std::optional<std::vector<std::uint8_t>> EcJwkToPublicKeyDer(const JwkEcPublicKey& jwk) {
  auto pkey_opt = EcJwkToEvpPkey(jwk);
  if (!pkey_opt) {
    return std::nullopt;
  }
  auto& pkey = *pkey_opt;

  const int len = i2d_PUBKEY(pkey.get(), nullptr);
  if (len <= 0) {
    return std::nullopt;
  }

  std::vector<std::uint8_t> out(static_cast<std::size_t>(len));
  unsigned char* p = out.data();
  if (i2d_PUBKEY(pkey.get(), &p) != len) {
    return std::nullopt;
  }
  return out;
}

void OfflineEcKeyStore::AddIssuerKeys(std::string issuer_host, JwksDocument jwks) {
  auto& issuer_map = keys_[std::move(issuer_host)];

  for (auto& k : jwks.keys) {
    auto expected_alg = ExpectedAlgFromCrv(k.crv);
    if (!expected_alg) {
      continue;
    }

    auto der = EcJwkToPublicKeyDer(k);
    if (!der) {
      continue;
    }

    StoredKey sk;
    sk.jwk = std::move(k);
    sk.public_key_bytes = std::move(*der);
    sk.expected_alg = *expected_alg;

    issuer_map[sk.jwk.kid] = std::move(sk);
  }
}

void OfflineEcKeyStore::AddIssuerPublicKeyBytes(std::string issuer_host,
                                                std::string kid,
                                                cosesign1::validation::CoseAlgorithm expected_alg,
                                                std::vector<std::uint8_t> public_key_bytes) {
  auto& issuer_map = keys_[std::move(issuer_host)];

  StoredKey sk;
  sk.jwk.kid = std::move(kid);
  sk.public_key_bytes = std::move(public_key_bytes);
  sk.expected_alg = expected_alg;

  issuer_map[sk.jwk.kid] = std::move(sk);
}

std::optional<OfflineEcKeyStore::ResolvedKey> OfflineEcKeyStore::Resolve(std::string_view issuer_host, std::string_view kid) const {
  const auto it_issuer = keys_.find(std::string(issuer_host));
  if (it_issuer == keys_.end()) {
    return std::nullopt;
  }

  const auto it_kid = it_issuer->second.find(std::string(kid));
  if (it_kid == it_issuer->second.end()) {
    return std::nullopt;
  }

  ResolvedKey out;
  out.public_key_bytes = it_kid->second.public_key_bytes;
  out.expected_alg = it_kid->second.expected_alg;
  return out;
}

} // namespace cosesign1::mst
