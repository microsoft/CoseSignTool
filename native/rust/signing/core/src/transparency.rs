// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Transparency provider abstractions for COSE_Sign1 messages.
//!
//! Maps V2 C# transparency abstractions from CoseSign1.Abstractions.Transparency to Rust.
//! Provides traits and utilities for augmenting COSE_Sign1 messages with transparency proofs
//! (e.g., MST receipts) and verifying them.

use tracing::{info};

use std::collections::{HashMap, HashSet};

use cose_sign1_primitives::{CoseSign1Message, CoseHeaderLabel, CoseHeaderValue};

/// COSE header label for receipts array (label 394).
pub const RECEIPTS_HEADER_LABEL: i64 = 394;

/// Error type for transparency operations.
#[derive(Debug)]
pub enum TransparencyError {
    /// Transparency submission failed.
    SubmissionFailed(String),
    /// Transparency verification failed.
    VerificationFailed(String),
    /// Invalid COSE message.
    InvalidMessage(String),
    /// Provider-specific error.
    ProviderError(String),
}

impl std::fmt::Display for TransparencyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SubmissionFailed(s) => write!(f, "transparency submission failed: {}", s),
            Self::VerificationFailed(s) => write!(f, "transparency verification failed: {}", s),
            Self::InvalidMessage(s) => write!(f, "invalid message: {}", s),
            Self::ProviderError(s) => write!(f, "provider error: {}", s),
        }
    }
}

impl std::error::Error for TransparencyError {}

/// Result of transparency proof verification.
#[derive(Debug, Clone)]
pub struct TransparencyValidationResult {
    /// Whether the transparency proof is valid.
    pub is_valid: bool,
    /// Validation errors, if any.
    pub errors: Vec<String>,
    /// Name of the transparency provider that performed validation.
    pub provider_name: String,
    /// Optional metadata about the validation.
    pub metadata: Option<HashMap<String, String>>,
}

impl TransparencyValidationResult {
    /// Creates a successful validation result.
    pub fn success(provider_name: impl Into<String>) -> Self {
        Self {
            is_valid: true,
            errors: vec![],
            provider_name: provider_name.into(),
            metadata: None,
        }
    }

    /// Creates a successful validation result with metadata.
    pub fn success_with_metadata(
        provider_name: impl Into<String>,
        metadata: HashMap<String, String>,
    ) -> Self {
        Self {
            is_valid: true,
            errors: vec![],
            provider_name: provider_name.into(),
            metadata: Some(metadata),
        }
    }

    /// Creates a failed validation result with errors.
    pub fn failure(provider_name: impl Into<String>, errors: Vec<String>) -> Self {
        Self {
            is_valid: false,
            errors,
            provider_name: provider_name.into(),
            metadata: None,
        }
    }
}

/// Trait for transparency providers that augment COSE_Sign1 messages with proofs.
///
/// Maps V2 `ITransparencyProvider`. Implementations:
/// - MST (Microsoft Signing Transparency)
/// - CSS (Confidential Signing Service) - future
pub trait TransparencyProvider: Send + Sync {
    /// Returns the name of this transparency provider.
    fn provider_name(&self) -> &str;

    /// Adds a transparency proof to a COSE_Sign1 message.
    ///
    /// # Arguments
    ///
    /// * `cose_bytes` - The CBOR-encoded COSE_Sign1 message
    ///
    /// # Returns
    ///
    /// The COSE_Sign1 message with the transparency proof added, or an error.
    fn add_transparency_proof(&self, cose_bytes: &[u8]) -> Result<Vec<u8>, TransparencyError>;

    /// Verifies the transparency proof in a COSE_Sign1 message.
    ///
    /// # Arguments
    ///
    /// * `cose_bytes` - The CBOR-encoded COSE_Sign1 message with proof
    ///
    /// # Returns
    ///
    /// Validation result indicating success or failure.
    fn verify_transparency_proof(
        &self,
        cose_bytes: &[u8],
    ) -> Result<TransparencyValidationResult, TransparencyError>;
}

/// Extracts receipts from a COSE_Sign1 message's unprotected headers.
///
/// Looks for the receipts array at header label 394.
///
/// # Arguments
///
/// * `msg` - The parsed COSE_Sign1 message
///
/// # Returns
///
/// A vector of receipt byte arrays. Empty if no receipts are present.
pub fn extract_receipts(msg: &CoseSign1Message) -> Vec<Vec<u8>> {
    match msg
        .unprotected
        .get(&CoseHeaderLabel::Int(RECEIPTS_HEADER_LABEL))
    {
        Some(CoseHeaderValue::Array(arr)) => arr
            .iter()
            .filter_map(|v| match v {
                CoseHeaderValue::Bytes(b) => Some(b.clone()),
                _ => None,
            })
            .collect(),
        _ => vec![],
    }
}

/// Merges additional receipts into a COSE_Sign1 message.
///
/// Deduplicates receipts by byte content. Updates the unprotected header
/// with the merged receipts array.
///
/// # Arguments
///
/// * `msg` - The COSE_Sign1 message to update
/// * `additional_receipts` - New receipts to merge in
pub fn merge_receipts(msg: &mut CoseSign1Message, additional_receipts: &[Vec<u8>]) {
    let mut existing = extract_receipts(msg);
    let mut seen: HashSet<Vec<u8>> = existing.iter().cloned().collect();

    for receipt in additional_receipts {
        if !receipt.is_empty() && seen.insert(receipt.clone()) {
            existing.push(receipt.clone());
        }
    }

    if existing.is_empty() {
        return;
    }

    msg.unprotected
        .remove(&CoseHeaderLabel::Int(RECEIPTS_HEADER_LABEL));
    msg.unprotected.insert(
        CoseHeaderLabel::Int(RECEIPTS_HEADER_LABEL),
        CoseHeaderValue::Array(existing.into_iter().map(CoseHeaderValue::Bytes).collect()),
    );
}

/// Adds a transparency proof while preserving existing receipts.
///
/// This utility function wraps a provider's `add_transparency_proof` call
/// and ensures that any pre-existing receipts are merged back into the result.
/// Maps V2 `TransparencyProviderBase` receipt preservation logic.
///
/// # Arguments
///
/// * `provider` - The transparency provider to use
/// * `cose_bytes` - The CBOR-encoded COSE_Sign1 message
///
/// # Returns
///
/// The COSE_Sign1 message with the new proof added and existing receipts preserved.
pub fn add_proof_with_receipt_merge(
    provider: &dyn TransparencyProvider,
    cose_bytes: &[u8],
) -> Result<Vec<u8>, TransparencyError> {
    info!(provider = provider.provider_name(), "Applying transparency proof");
    
    let existing_receipts = match CoseSign1Message::parse(cose_bytes) {
        Ok(msg) => extract_receipts(&msg),
        Err(_) => vec![],
    };

    let result_bytes = provider.add_transparency_proof(cose_bytes)?;

    if existing_receipts.is_empty() {
        return Ok(result_bytes);
    }

    let mut result_msg = CoseSign1Message::parse(&result_bytes)
        .map_err(|e| TransparencyError::InvalidMessage(e.to_string()))?;

    merge_receipts(&mut result_msg, &existing_receipts);

    result_msg
        .encode(true)
        .map_err(|e| TransparencyError::InvalidMessage(e.to_string()))
}
