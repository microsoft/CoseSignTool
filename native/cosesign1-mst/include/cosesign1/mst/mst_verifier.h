// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#pragma once

/**
 * @file mst_verifier.h
 * @brief Verification entry points for Microsoft Signing Transparency (MST) receipts.
 */

#include <cstdint>
#include <string_view>
#include <vector>

#include "cosesign1/mst/jwk_ec_key.h"
#include "cosesign1/mst/jwks_fetcher.h"
#include "cosesign1/mst/online_key_resolver.h"
#include "cosesign1/mst/verification_options.h"
#include "cosesign1/validation/validation_result.h"

namespace cosesign1::mst {

/**
 * @brief Verifies MST receipts embedded in a COSE_Sign1 transparent statement.
 *
 * This mimics the receipt selection and behavior rules of the .NET
 * `CodeTransparencyClient.VerifyTransparentStatement` API, but operates offline:
 * keys must be provided via OfflineEcKeyStore.
 */
cosesign1::validation::ValidationResult VerifyTransparentStatement(
    std::string_view validator_name,
    const std::vector<std::uint8_t>& transparent_statement_cose_sign1,
    const OfflineEcKeyStore& key_store,
    const VerificationOptions& options);

/**
 * @brief Same as VerifyTransparentStatement, with optional HTTPS JWKS fallback.
 *
 * - @p key_cache is an offline-first cache populated with JWKS data fetched over the network.
 * - Network fetch occurs only when @p options.allow_network_key_fetch is true.
 * - Fetch uses `https://{issuer}{options.jwks_path}`.
 */
cosesign1::validation::ValidationResult VerifyTransparentStatementOnline(
    std::string_view validator_name,
    const std::vector<std::uint8_t>& transparent_statement_cose_sign1,
    OfflineEcKeyStore& key_cache,
    const IJwksFetcher& jwks_fetcher,
    const VerificationOptions& options);

/**
 * @brief Convenience overload that uses GetDefaultJwksFetcher().
 */
cosesign1::validation::ValidationResult VerifyTransparentStatementOnline(
    std::string_view validator_name,
    const std::vector<std::uint8_t>& transparent_statement_cose_sign1,
    OfflineEcKeyStore& key_cache,
    const VerificationOptions& options);

/**
 * @brief Verifies a single MST receipt against detached signed claims bytes.
 *
 * This is analogous to the Azure SDK
 * `CcfReceiptVerifier.VerifyTransparentStatementReceipt` behavior.
 *
 * Validation performed:
 * - Receipt structure
 * - Receipt signature over the accumulator (detached payload)
 * - Leaf data hash matches sha256(input_signed_claims)
 * - Receipt KID matches the provided key KID
 */
cosesign1::validation::ValidationResult VerifyTransparentStatementReceipt(
    std::string_view validator_name,
    const JwkEcPublicKey& key,
    const std::vector<std::uint8_t>& receipt_cose_sign1,
    const std::vector<std::uint8_t>& input_signed_claims);

} // namespace cosesign1::mst
