// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Verification options for transparent statement validation.
//!
//! Port of C# `Azure.Security.CodeTransparency.CodeTransparencyVerificationOptions`.

use code_transparency_client::{JwksDocument, OfflineKeysBehavior};
use std::collections::HashMap;

/// Controls what happens when a receipt is from an authorized domain.
///
/// Maps C# `Azure.Security.CodeTransparency.AuthorizedReceiptBehavior`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthorizedReceiptBehavior {
    /// At least one receipt from any authorized domain must verify successfully.
    VerifyAnyMatching,
    /// All receipts from authorized domains must verify successfully.
    VerifyAllMatching,
    /// Every authorized domain must have at least one valid receipt.
    RequireAll,
}

impl Default for AuthorizedReceiptBehavior {
    fn default() -> Self { Self::RequireAll }
}

/// Controls what happens when a receipt is from an unauthorized domain.
///
/// Maps C# `Azure.Security.CodeTransparency.UnauthorizedReceiptBehavior`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnauthorizedReceiptBehavior {
    /// Verify unauthorized receipts but don't fail if they're invalid.
    VerifyAll,
    /// Skip unauthorized receipts entirely.
    IgnoreAll,
    /// Fail immediately if any unauthorized receipt is present.
    FailIfPresent,
}

impl Default for UnauthorizedReceiptBehavior {
    fn default() -> Self { Self::VerifyAll }
}

/// Options controlling transparent statement verification.
///
/// Maps C# `Azure.Security.CodeTransparency.CodeTransparencyVerificationOptions`.
#[derive(Debug, Clone, Default)]
pub struct CodeTransparencyVerificationOptions {
    /// List of authorized issuer domains. If empty, all issuers are treated as authorized.
    pub authorized_domains: Vec<String>,
    /// How to handle receipts from authorized domains.
    pub authorized_receipt_behavior: AuthorizedReceiptBehavior,
    /// How to handle receipts from unauthorized domains.
    pub unauthorized_receipt_behavior: UnauthorizedReceiptBehavior,
    /// Offline JWKS documents keyed by issuer host, for verification without network calls.
    pub offline_keys: Option<HashMap<String, JwksDocument>>,
    /// Controls offline key fallback behavior.
    pub offline_keys_behavior: OfflineKeysBehavior,
}
