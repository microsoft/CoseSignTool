#include "cosesign1/mst/jwks_fetcher.h"

#include <cstdint>
#include <string>

#include <curl/curl.h>

namespace cosesign1::mst {

namespace {

size_t WriteCallback(char* ptr, size_t size, size_t nmemb, void* userdata) {
  auto* out = static_cast<std::string*>(userdata);
  const size_t total = size * nmemb;
  out->append(ptr, total);
  return total;
}

std::string NormalizePath(std::string_view path) {
  if (path.empty()) {
    return "/jwks";
  }
  if (path.front() == '/') {
    return std::string(path);
  }
  return std::string("/") + std::string(path);
}

} // namespace

class CurlJwksFetcher final : public IJwksFetcher {
 public:
  std::optional<std::string> FetchJwksJson(std::string_view issuer_host,
                                          std::string_view jwks_path,
                                          std::uint32_t timeout_ms,
                                          std::string& out_error) const override {
    out_error.clear();

    const std::string url = std::string("https://") + std::string(issuer_host) + NormalizePath(jwks_path);

    CURL* curl = curl_easy_init();
    if (!curl) {
      out_error = "curl_easy_init failed";
      return std::nullopt;
    }

    std::string body;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, &WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &body);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, static_cast<long>(timeout_ms));
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "cosesign1-mst/0.1");

    const CURLcode rc = curl_easy_perform(curl);
    if (rc != CURLE_OK) {
      out_error = curl_easy_strerror(rc);
      curl_easy_cleanup(curl);
      return std::nullopt;
    }

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (http_code < 200 || http_code >= 300) {
      out_error = "HTTP " + std::to_string(http_code);
      return std::nullopt;
    }

    return body;
  }
};

// Factory function exposed via translation unit symbol.
const IJwksFetcher& GetDefaultJwksFetcher() {
  static CurlJwksFetcher f;
  return f;
}

} // namespace cosesign1::mst
