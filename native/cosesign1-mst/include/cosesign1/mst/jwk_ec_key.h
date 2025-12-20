#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "cosesign1/validation/cose_sign1_verifier.h"

namespace cosesign1::mst {

struct JwkEcPublicKey {
  std::string kid;
  std::string crv;      // e.g. "P-256"
  std::string kty;      // must be "EC"
  std::string x_b64url; // base64url
  std::string y_b64url; // base64url
};

struct JwksDocument {
  std::vector<JwkEcPublicKey> keys;
};

// Parses a JWKS JSON document (RFC 7517).
// Supported key form:
// - EC JWKs with (kty=EC, crv, x, y)
std::optional<JwksDocument> ParseJwks(std::string_view jwks_json);

// Converts an EC JWK public key (x/y coordinates) into a PEM-encoded SubjectPublicKeyInfo.
std::optional<std::string> EcJwkToPublicKeyPem(const JwkEcPublicKey& jwk);

// Converts an EC JWK public key (x/y coordinates) into DER-encoded SubjectPublicKeyInfo.
std::optional<std::vector<std::uint8_t>> EcJwkToPublicKeyDer(const JwkEcPublicKey& jwk);

// Determines the expected COSE algorithm from an EC curve name.
std::optional<cosesign1::validation::CoseAlgorithm> ExpectedAlgFromCrv(std::string_view crv);

class OfflineEcKeyStore {
 public:
  void AddIssuerKeys(std::string issuer_host, JwksDocument jwks);

  // Adds a non-EC (e.g., PQC) public key by raw bytes.
  // `expected_alg` should match the receipt COSE 'alg' header.
  void AddIssuerPublicKeyBytes(std::string issuer_host,
                               std::string kid,
                               cosesign1::validation::CoseAlgorithm expected_alg,
                               std::vector<std::uint8_t> public_key_bytes);

  struct ResolvedKey {
    std::optional<std::vector<std::uint8_t>> public_key_bytes;
    std::optional<cosesign1::validation::CoseAlgorithm> expected_alg;
  };

  std::optional<ResolvedKey> Resolve(std::string_view issuer_host, std::string_view kid) const;

 private:
  struct StoredKey {
    JwkEcPublicKey jwk;
    std::optional<std::vector<std::uint8_t>> public_key_bytes;
    std::optional<cosesign1::validation::CoseAlgorithm> expected_alg;
  };

  // issuer -> (kid -> key)
  std::unordered_map<std::string, std::unordered_map<std::string, StoredKey>> keys_;
};

} // namespace cosesign1::mst
