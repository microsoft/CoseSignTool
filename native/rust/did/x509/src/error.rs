// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// Errors that can occur when parsing or validating DID:x509 identifiers.
#[derive(Debug, PartialEq)]
pub enum DidX509Error {
    EmptyDid,
    InvalidPrefix(String),
    MissingPolicies,
    InvalidFormat(String),
    UnsupportedVersion(String, String),
    UnsupportedHashAlgorithm(String),
    EmptyFingerprint,
    FingerprintLengthMismatch(String, usize, usize),
    InvalidFingerprintChars,
    EmptyPolicy(usize),
    InvalidPolicyFormat(String),
    EmptyPolicyName,
    EmptyPolicyValue,
    InvalidSubjectPolicyComponents,
    EmptySubjectPolicyKey,
    DuplicateSubjectPolicyKey(String),
    InvalidSanPolicyFormat(String),
    InvalidSanType(String),
    InvalidEkuOid,
    EmptyFulcioIssuer,
    PercentDecodingError(String),
    InvalidHexCharacter(char),
    InvalidChain(String),
    CertificateParseError(String),
    PolicyValidationFailed(String),
    NoCaMatch,
    ValidationFailed(String),
}

impl std::fmt::Display for DidX509Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DidX509Error::EmptyDid => write!(f, "DID cannot be null or empty"),
            DidX509Error::InvalidPrefix(prefix) => {
                write!(f, "Invalid DID: must start with '{}':", prefix)
            }
            DidX509Error::MissingPolicies => {
                write!(f, "Invalid DID: must contain at least one policy")
            }
            DidX509Error::InvalidFormat(format) => {
                write!(f, "Invalid DID: expected format '{}'", format)
            }
            DidX509Error::UnsupportedVersion(got, expected) => write!(
                f,
                "Invalid DID: unsupported version '{}', expected '{}'",
                got, expected
            ),
            DidX509Error::UnsupportedHashAlgorithm(algo) => {
                write!(f, "Invalid DID: unsupported hash algorithm '{}'", algo)
            }
            DidX509Error::EmptyFingerprint => {
                write!(f, "Invalid DID: CA fingerprint cannot be empty")
            }
            DidX509Error::FingerprintLengthMismatch(algo, expected, got) => write!(
                f,
                "Invalid DID: CA fingerprint length mismatch for {} (expected {}, got {})",
                algo, expected, got
            ),
            DidX509Error::InvalidFingerprintChars => write!(
                f,
                "Invalid DID: CA fingerprint contains invalid base64url characters"
            ),
            DidX509Error::EmptyPolicy(pos) => {
                write!(f, "Invalid DID: empty policy at position {}", pos)
            }
            DidX509Error::InvalidPolicyFormat(format) => {
                write!(f, "Invalid DID: policy must have format '{}'", format)
            }
            DidX509Error::EmptyPolicyName => write!(f, "Invalid DID: policy name cannot be empty"),
            DidX509Error::EmptyPolicyValue => {
                write!(f, "Invalid DID: policy value cannot be empty")
            }
            DidX509Error::InvalidSubjectPolicyComponents => write!(
                f,
                "Invalid subject policy: must have even number of components (key:value pairs)"
            ),
            DidX509Error::EmptySubjectPolicyKey => {
                write!(f, "Invalid subject policy: key cannot be empty")
            }
            DidX509Error::DuplicateSubjectPolicyKey(key) => {
                write!(f, "Invalid subject policy: duplicate key '{}'", key)
            }
            DidX509Error::InvalidSanPolicyFormat(format) => {
                write!(f, "Invalid SAN policy: must have format '{}'", format)
            }
            DidX509Error::InvalidSanType(san_type) => write!(
                f,
                "Invalid SAN policy: SAN type must be 'email', 'dns', 'uri', or 'dn' (got '{}')",
                san_type
            ),
            DidX509Error::InvalidEkuOid => write!(
                f,
                "Invalid EKU policy: must be a valid OID in dotted decimal notation"
            ),
            DidX509Error::EmptyFulcioIssuer => {
                write!(f, "Invalid Fulcio issuer policy: issuer cannot be empty")
            }
            DidX509Error::PercentDecodingError(msg) => write!(f, "Percent decoding error: {}", msg),
            DidX509Error::InvalidHexCharacter(ch) => write!(f, "Invalid hex character: {}", ch),
            DidX509Error::InvalidChain(msg) => write!(f, "Invalid chain: {}", msg),
            DidX509Error::CertificateParseError(msg) => {
                write!(f, "Certificate parse error: {}", msg)
            }
            DidX509Error::PolicyValidationFailed(msg) => {
                write!(f, "Policy validation failed: {}", msg)
            }
            DidX509Error::NoCaMatch => write!(f, "No CA certificate in chain matches fingerprint"),
            DidX509Error::ValidationFailed(msg) => write!(f, "Validation failed: {}", msg),
        }
    }
}

impl std::error::Error for DidX509Error {}
