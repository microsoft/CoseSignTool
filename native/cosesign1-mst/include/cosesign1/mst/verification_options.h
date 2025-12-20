#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace cosesign1::mst {

enum class AuthorizedReceiptBehavior {
  VerifyAnyMatching,
  VerifyAllMatching,
  RequireAll,
};

enum class UnauthorizedReceiptBehavior {
  VerifyAll,
  IgnoreAll,
  FailIfPresent,
};

struct VerificationOptions {
  std::vector<std::string> authorized_domains;

  // If true, the verifier may download issuer JWKS over HTTPS when a key is not present
  // in the provided offline key store. Network fetch is only attempted for issuers that
  // are considered authorized by `authorized_domains`.
  bool allow_network_key_fetch = false;

  // Relative path for the JWKS endpoint (Azure Code Transparency uses "/jwks").
  std::string jwks_path = "/jwks";

  // Network timeout for JWKS retrieval.
  std::uint32_t jwks_timeout_ms = 5000;

  AuthorizedReceiptBehavior authorized_receipt_behavior = AuthorizedReceiptBehavior::RequireAll;
  UnauthorizedReceiptBehavior unauthorized_receipt_behavior = UnauthorizedReceiptBehavior::FailIfPresent;
};

} // namespace cosesign1::mst
