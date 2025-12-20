// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/**
 * @file jwks_fetcher.h
 * @brief Abstractions for retrieving JWKS documents over the network.
 */

#include <optional>
#include <string>
#include <string_view>

#include <cstdint>

namespace cosesign1::mst {

/**
 * @brief Fetches a JWKS JSON document from an issuer.
 *
 * This is intentionally abstracted so the core library can be used in environments
 * without a specific HTTP stack.
 */
class IJwksFetcher {
 public:
  virtual ~IJwksFetcher() = default;

    /**
     * @brief Fetches the JWKS JSON document for the given issuer host.
     *
     * Implementations should perform an HTTPS GET to `https://{issuer_host}{jwks_path}`.
     *
     * @param issuer_host Issuer host name (e.g. "example.azure.com").
     * @param jwks_path Relative JWKS path (e.g. "/jwks").
     * @param timeout_ms Network timeout.
     * @param out_error Optional human-readable error message.
     * @return JWKS JSON string on success; std::nullopt on failure.
     */
  virtual std::optional<std::string> FetchJwksJson(std::string_view issuer_host,
                                                   std::string_view jwks_path,
                                                   std::uint32_t timeout_ms,
                                                   std::string& out_error) const = 0;
};

/**
 * @brief Returns the library's default JWKS fetcher implementation (libcurl-based).
 */
const IJwksFetcher& GetDefaultJwksFetcher();

} // namespace cosesign1::mst
