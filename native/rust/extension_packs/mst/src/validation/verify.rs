// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Static verification of transparent statements.
//!
//! Port of C# `CodeTransparencyClient.VerifyTransparentStatement()`.
//!
//! This module provides:
//! - [`get_receipts_from_transparent_statement`] — extract receipts from COSE unprotected headers
//! - [`get_receipt_issuer_host`] — extract the issuer host from a receipt's CWT claims
//! - [`verify_transparent_statement`] — orchestrate per-issuer verification with policy

use crate::validation::receipt_verify::{
    get_cwt_issuer_host, verify_mst_receipt, ReceiptVerifyError, ReceiptVerifyInput,
    CWT_CLAIMS_LABEL, CWT_ISS_LABEL,
};
use crate::validation::verification_options::{
    AuthorizedReceiptBehavior, CodeTransparencyVerificationOptions, UnauthorizedReceiptBehavior,
};
use code_transparency_client::{
    CodeTransparencyClient, CodeTransparencyClientConfig, CodeTransparencyClientOptions,
    OfflineKeysBehavior,
};
use cose_sign1_primitives::CoseSign1Message;
use cose_sign1_signing::transparency::extract_receipts;
use std::collections::{HashMap, HashSet};

/// Prefix for receipts with unknown/unrecognized issuers.
pub const UNKNOWN_ISSUER_PREFIX: &str = "__unknown-issuer::";

/// Extract receipts from a transparent statement's COSE unprotected headers.
///
/// Returns a list of `(issuer_host, receipt_bytes)` tuples.
/// Receipts with unparseable issuers get a synthetic `__unknown-issuer::N` prefix.
///
/// Maps C# `GetReceiptsFromTransparentStatementStatic`.
pub fn get_receipts_from_transparent_statement(
    transparent_statement_bytes: &[u8],
) -> Result<Vec<ExtractedReceipt>, String> {
    let msg = CoseSign1Message::parse(transparent_statement_bytes)
        .map_err(|e| format!("failed to parse transparent statement: {}", e))?;
    get_receipts_from_message(&msg)
}

/// A receipt extracted from a transparent statement, already parsed.
pub struct ExtractedReceipt {
    /// The issuer host from the receipt's CWT claims, or a synthetic
    /// `__unknown-issuer::N` identifier if the issuer could not be parsed.
    pub issuer: String,
    /// The raw receipt bytes (for downstream verification).
    pub raw_bytes: Vec<u8>,
    /// The parsed receipt as a [`CoseSign1Message`], or `None` if parsing failed.
    pub message: Option<CoseSign1Message>,
}

impl std::fmt::Debug for ExtractedReceipt {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtractedReceipt")
            .field("issuer", &self.issuer)
            .field("raw_bytes_len", &self.raw_bytes.len())
            .finish()
    }
}

/// Extract receipts from an already-parsed [`CoseSign1Message`].
///
/// Returns fully parsed [`ExtractedReceipt`] objects with issuer, raw bytes,
/// and a parsed `CoseSign1Message` for each receipt.
///
/// Receipts that fail to parse as COSE_Sign1 are still included with a
/// synthetic `__unknown-issuer::N` issuer and best-effort fields.
pub fn get_receipts_from_message(
    msg: &CoseSign1Message,
) -> Result<Vec<ExtractedReceipt>, String> {
    let receipt_blobs = extract_receipts(msg);
    let mut result = Vec::new();

    for (idx, receipt_bytes) in receipt_blobs.into_iter().enumerate() {
        let parsed = CoseSign1Message::parse(&receipt_bytes);

        let issuer = match &parsed {
            Ok(receipt_msg) => {
                get_cwt_issuer_host(&receipt_msg.protected, CWT_CLAIMS_LABEL, CWT_ISS_LABEL)
                    .unwrap_or_else(|| format!("{}{}", UNKNOWN_ISSUER_PREFIX, idx))
            }
            Err(_) => format!("{}{}", UNKNOWN_ISSUER_PREFIX, idx),
        };

        let message = parsed.ok();

        result.push(ExtractedReceipt {
            issuer,
            raw_bytes: receipt_bytes,
            message,
        });
    }

    Ok(result)
}

/// Extract the issuer host from a receipt's CWT claims.
///
/// Maps C# `GetReceiptIssuerHostStatic`.
pub fn get_receipt_issuer_host(receipt_bytes: &[u8]) -> Result<String, String> {
    let receipt = CoseSign1Message::parse(receipt_bytes)
        .map_err(|e| format!("failed to parse receipt: {}", e))?;

    get_cwt_issuer_host(&receipt.protected, CWT_CLAIMS_LABEL, CWT_ISS_LABEL)
        .ok_or_else(|| "issuer not found in receipt CWT claims".to_string())
}

/// Verify a transparent statement using the full C# verification logic.
///
/// Maps C# `CodeTransparencyClient.VerifyTransparentStatement(bytes, options, clientOptions)`.
///
/// This function:
/// 1. Extracts receipts from the transparent statement
/// 2. Creates per-issuer `CodeTransparencyClient` instances
/// 3. For each receipt, resolves the signing key and verifies the receipt
/// 4. Applies authorized/unauthorized domain policies per the options
///
/// # Errors
///
/// Returns a `Vec<String>` of all verification failures encountered.
pub fn verify_transparent_statement(
    transparent_statement_bytes: &[u8],
    options: Option<CodeTransparencyVerificationOptions>,
    client_options: Option<CodeTransparencyClientOptions>,
) -> Result<(), Vec<String>> {
    let msg = CoseSign1Message::parse(transparent_statement_bytes)
        .map_err(|e| vec![format!("failed to parse transparent statement: {}", e)])?;
    verify_transparent_statement_message(
        &msg,
        transparent_statement_bytes,
        options,
        client_options,
    )
}

/// Verify an already-parsed transparent statement.
///
/// Same as [`verify_transparent_statement`] but avoids re-parsing when the
/// caller already has a parsed [`CoseSign1Message`].
///
/// `raw_bytes` must be the original serialized bytes of `msg` (needed for
/// receipt digest computation).
pub fn verify_transparent_statement_message(
    msg: &CoseSign1Message,
    raw_bytes: &[u8],
    options: Option<CodeTransparencyVerificationOptions>,
    client_options: Option<CodeTransparencyClientOptions>,
) -> Result<(), Vec<String>> {
    let options = options.unwrap_or_default();
    let client_options = client_options.unwrap_or_default();

    // 1. Extract receipts
    let receipt_list = get_receipts_from_message(msg)
        .map_err(|e| vec![e])?;

    if receipt_list.is_empty() {
        return Err(vec!["No receipts found in the transparent statement.".to_string()]);
    }

    // 2. Build authorized domain set
    let authorized_set: HashSet<String> = options
        .authorized_domains
        .iter()
        .filter(|d| !d.is_empty() && !d.starts_with(UNKNOWN_ISSUER_PREFIX))
        .map(|d| d.trim().to_lowercase())
        .collect();
    let user_provided_authorized = !authorized_set.is_empty();

    // Guard: no authorized domains + IgnoreAll would verify nothing
    if authorized_set.is_empty()
        && options.unauthorized_receipt_behavior == UnauthorizedReceiptBehavior::IgnoreAll
    {
        return Err(vec![
            "No receipts would be verified: no authorized domains and unauthorized behavior is IgnoreAll."
                .to_string(),
        ]);
    }

    // 3. Early fail on unauthorized receipts if FailIfPresent
    if options.unauthorized_receipt_behavior == UnauthorizedReceiptBehavior::FailIfPresent
        && user_provided_authorized
    {
        for receipt in &receipt_list {
            if !authorized_set.contains(&receipt.issuer.to_lowercase()) {
                return Err(vec![format!(
                    "Receipt issuer '{}' is not in the authorized domain list.",
                    receipt.issuer
                )]);
            }
        }
    }

    // 4. Verify receipts
    let mut authorized_failures = Vec::new();
    let mut unauthorized_failures = Vec::new();
    let mut valid_authorized_domains: HashSet<String> = HashSet::new();
    let mut authorized_domains_with_receipt: HashSet<String> = HashSet::new();
    let mut client_cache: HashMap<String, CodeTransparencyClient> = HashMap::new();

    for receipt in &receipt_list {
        let issuer = &receipt.issuer;
        let receipt_bytes = &receipt.raw_bytes;
        let issuer_lower = issuer.to_lowercase();
        let is_authorized = !user_provided_authorized || authorized_set.contains(&issuer_lower);

        if is_authorized && user_provided_authorized {
            authorized_domains_with_receipt.insert(issuer_lower.clone());
        }

        // Determine if this receipt should be verified
        let should_verify = if is_authorized {
            true
        } else {
            match options.unauthorized_receipt_behavior {
                UnauthorizedReceiptBehavior::VerifyAll => true,
                UnauthorizedReceiptBehavior::IgnoreAll => false,
                UnauthorizedReceiptBehavior::FailIfPresent => false, // handled above
            }
        };

        if !should_verify {
            continue;
        }

        if issuer.starts_with(UNKNOWN_ISSUER_PREFIX) {
            unauthorized_failures.push(format!(
                "Cannot verify receipt with unknown issuer '{}'.",
                issuer
            ));
            continue;
        }

        // Get or create client for this issuer
        let client = client_cache.entry(issuer.clone()).or_insert_with(|| {
            let endpoint = url::Url::parse(&format!("https://{}", issuer))
                .unwrap_or_else(|_| url::Url::parse("https://invalid").unwrap());

            let mut config = CodeTransparencyClientConfig::default();
            if let Some(ref offline) = options.offline_keys {
                config.offline_keys = Some(offline.clone());
            }
            config.offline_keys_behavior = options.offline_keys_behavior;

            CodeTransparencyClient::with_options(endpoint, config, client_options.clone())
        });

        // Build ReceiptVerifyInput using the client for JWKS resolution
        let input = ReceiptVerifyInput {
            statement_bytes_with_receipts: raw_bytes,
            receipt_bytes,
            offline_jwks_json: None,
            allow_network_fetch: options.offline_keys_behavior != OfflineKeysBehavior::OfflineOnly,
            jwks_api_version: None,
            client: Some(client),
        };

        match verify_mst_receipt(input) {
            Ok(result) if result.trusted => {
                if is_authorized {
                    valid_authorized_domains.insert(issuer_lower);
                }
            }
            Ok(_) => {
                let msg = format!("Receipt from '{}' did not verify as trusted.", issuer);
                if is_authorized {
                    authorized_failures.push(msg);
                } else {
                    unauthorized_failures.push(msg);
                }
            }
            Err(e) => {
                let msg = format!("Receipt verification failed for '{}': {}", issuer, e);
                if is_authorized {
                    authorized_failures.push(msg);
                } else {
                    unauthorized_failures.push(msg);
                }
            }
        }
    }

    // 5. Apply authorized-domain policy
    if user_provided_authorized {
        match options.authorized_receipt_behavior {
            AuthorizedReceiptBehavior::VerifyAnyMatching => {
                if valid_authorized_domains.is_empty() {
                    authorized_failures.push(
                        "No valid receipts found for any authorized issuer domain.".to_string(),
                    );
                } else {
                    // At least one valid → clear authorized failures
                    authorized_failures.clear();
                }
            }
            AuthorizedReceiptBehavior::VerifyAllMatching => {
                if authorized_domains_with_receipt.is_empty() {
                    authorized_failures.push(
                        "No valid receipts found for any authorized issuer domain.".to_string(),
                    );
                }
                for domain in &authorized_domains_with_receipt {
                    if !valid_authorized_domains.contains(domain) {
                        authorized_failures.push(format!(
                            "A receipt from the required domain '{}' failed verification.",
                            domain
                        ));
                    }
                }
            }
            AuthorizedReceiptBehavior::RequireAll => {
                for domain in &authorized_set {
                    if !valid_authorized_domains.contains(domain) {
                        authorized_failures.push(format!(
                            "No valid receipt found for a required domain '{}'.",
                            domain
                        ));
                    }
                }
            }
        }
    }

    // 6. Combine failures
    let mut all_failures = Vec::new();
    all_failures.extend(authorized_failures);
    all_failures.extend(unauthorized_failures);

    if all_failures.is_empty() {
        Ok(())
    } else {
        Err(all_failures)
    }
}
