#include "cosesign1/mst/online_key_resolver.h"

#include <utility>

namespace cosesign1::mst {

OnlineKeyResolver::OnlineKeyResolver(OfflineEcKeyStore& cache, const IJwksFetcher& fetcher)
    : cache_(cache), fetcher_(fetcher) {}

std::optional<OfflineEcKeyStore::ResolvedKey> OnlineKeyResolver::Resolve(std::string_view issuer_host,
                                                                        std::string_view kid,
                                                                        bool allow_network_fetch,
                                                                        std::string_view jwks_path,
                                                                        std::uint32_t timeout_ms,
                                                                        std::string& out_error) {
  out_error.clear();

  if (auto k = cache_.Resolve(issuer_host, kid)) {
    return k;
  }

  if (!allow_network_fetch) {
    out_error = "key not found in offline store";
    return std::nullopt;
  }

  auto jwks_json = fetcher_.FetchJwksJson(issuer_host, jwks_path, timeout_ms, out_error);
  if (!jwks_json) {
    if (out_error.empty()) {
      out_error = "failed to fetch JWKS";
    }
    return std::nullopt;
  }

  auto jwks = ParseJwks(*jwks_json);
  if (!jwks) {
    out_error = "failed to parse JWKS";
    return std::nullopt;
  }

  cache_.AddIssuerKeys(std::string(issuer_host), std::move(*jwks));
  return cache_.Resolve(issuer_host, kid);
}

} // namespace cosesign1::mst
