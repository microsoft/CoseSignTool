// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/**
 * @file verification_options.h
 * @brief Options controlling MST verification behavior.
 */

#include <cstdint>
#include <string>
#include <vector>

namespace cosesign1::mst {

/**
 * @brief How to treat receipts whose issuer is considered authorized.
 */
enum class AuthorizedReceiptBehavior {
  VerifyAnyMatching,
  VerifyAllMatching,
  RequireAll,
};

/**
 * @brief How to treat receipts whose issuer is considered unauthorized.
 */
enum class UnauthorizedReceiptBehavior {
  VerifyAll,
  IgnoreAll,
  FailIfPresent,
};

/**
 * @brief Configuration for verifying transparent statements and receipts.
 */
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
