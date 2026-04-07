// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Signing errors.

use std::borrow::Cow;

/// Error type for signing operations.
#[derive(Debug)]
pub enum SigningError {
    /// Error related to key operations.
    KeyError { detail: Cow<'static, str> },

    /// Header contribution failed.
    HeaderContributionFailed { detail: Cow<'static, str> },

    /// Signing operation failed.
    SigningFailed { detail: Cow<'static, str> },

    /// Signature verification failed.
    VerificationFailed { detail: Cow<'static, str> },

    /// Invalid configuration.
    InvalidConfiguration { detail: Cow<'static, str> },
}

impl std::fmt::Display for SigningError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyError { detail } => write!(f, "Key error: {}", detail),
            Self::HeaderContributionFailed { detail } => {
                write!(f, "Header contribution failed: {}", detail)
            }
            Self::SigningFailed { detail } => write!(f, "Signing failed: {}", detail),
            Self::VerificationFailed { detail } => write!(f, "Verification failed: {}", detail),
            Self::InvalidConfiguration { detail } => {
                write!(f, "Invalid configuration: {}", detail)
            }
        }
    }
}

impl std::error::Error for SigningError {}
