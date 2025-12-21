// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/**
 * @file online_key_resolver.h
 * @brief Offline-first key resolution with optional JWKS network fallback.
 */

#include <optional>
#include <string>
#include <string_view>

#include "cosesign1/mst/jwk_ec_key.h"
#include "cosesign1/mst/jwks_fetcher.h"

namespace cosesign1::mst {

/**
 * @brief Offline-first key resolver with optional HTTPS JWKS fallback.
 *
 * Behavior is intentionally modeled after Azure's GetServiceCertificateKey:
 * - Resolve by (issuer_host, kid)
 * - Prefer offline cache
 * - If not found and network fetch allowed, download JWKS from the issuer and retry
 */
class OnlineKeyResolver {
 public:
  /**
  * @brief Constructs a resolver.
  * @param cache Cache that will be consulted first and updated after successful fetches.
  * @param fetcher Network fetch implementation.
  */
  OnlineKeyResolver(OfflineEcKeyStore& cache, const IJwksFetcher& fetcher);

  /**
   * @brief Resolves a key by issuer host and key ID.
   */
  std::optional<OfflineEcKeyStore::ResolvedKey> Resolve(std::string_view issuer_host,
                                                       std::string_view kid,
                                                       bool allow_network_fetch,
                                                       std::string_view jwks_path,
                                                       std::uint32_t timeout_ms,
                                                       std::string& out_error);

 private:
  OfflineEcKeyStore& cache_;
  const IJwksFetcher& fetcher_;
};

} // namespace cosesign1::mst
