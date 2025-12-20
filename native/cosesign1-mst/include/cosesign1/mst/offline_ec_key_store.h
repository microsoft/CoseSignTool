// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "cosesign1/mst/jwk_ec_public_key.h"
#include "cosesign1/mst/jwks_document.h"
#include "cosesign1/validation/cose_sign1_verifier.h"

namespace cosesign1::mst {

/**
 * @file offline_ec_key_store.h
 * @brief In-memory key store for mapping (issuer host, kid) -> public key.
 */

/**
 * @brief Stores issuer keys and resolves them by key ID.
 *
 * This is used by MST verification to locate issuer signing keys, without requiring
 * a network fetch at verification time.
 */
class OfflineEcKeyStore {
 public:
  /**
   * @brief Adds all keys from a JWKS document for the specified issuer.
   */
  void AddIssuerKeys(std::string issuer_host, JwksDocument jwks);

  /**
   * @brief Adds a non-EC (e.g., PQC) public key by raw bytes.
   *
   * @p expected_alg should match the receipt COSE 'alg' header.
   */
  void AddIssuerPublicKeyBytes(std::string issuer_host,
                               std::string kid,
                               cosesign1::validation::CoseAlgorithm expected_alg,
                               std::vector<std::uint8_t> public_key_bytes);

  /**
   * @brief Key resolution output.
   */
  struct ResolvedKey {
    std::optional<std::vector<std::uint8_t>> public_key_bytes;
    std::optional<cosesign1::validation::CoseAlgorithm> expected_alg;
  };

  /**
   * @brief Looks up a key for the given issuer host and key ID.
   */
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
