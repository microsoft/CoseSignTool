#pragma once

#include <optional>
#include <string>
#include <string_view>

#include <cstdint>

namespace cosesign1::mst {

class IJwksFetcher {
 public:
  virtual ~IJwksFetcher() = default;

  // Fetch the JWKS JSON document for the given issuer host (e.g. "example.azure.com").
  // Implementations should perform an HTTPS GET to `https://{issuer_host}{jwks_path}`.
  virtual std::optional<std::string> FetchJwksJson(std::string_view issuer_host,
                                                   std::string_view jwks_path,
                                                   std::uint32_t timeout_ms,
                                                   std::string& out_error) const = 0;
};

// Default implementation (libcurl-based). Defined in the library.
const IJwksFetcher& GetDefaultJwksFetcher();

} // namespace cosesign1::mst
