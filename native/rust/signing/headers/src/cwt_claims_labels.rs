// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// CWT (CBOR Web Token) Claims labels as defined in RFC 8392.
///
/// Maps V2 `CWTClaimsHeaderLabels`.
pub struct CWTClaimsHeaderLabels;

impl CWTClaimsHeaderLabels {
    /// Issuer claim label.
    pub const ISSUER: i64 = 1;
    
    /// Subject claim label.
    pub const SUBJECT: i64 = 2;
    
    /// Audience claim label.
    pub const AUDIENCE: i64 = 3;
    
    /// Expiration time claim label.
    pub const EXPIRATION_TIME: i64 = 4;
    
    /// Not before claim label.
    pub const NOT_BEFORE: i64 = 5;
    
    /// Issued at claim label.
    pub const ISSUED_AT: i64 = 6;
    
    /// CWT ID claim label.
    pub const CWT_ID: i64 = 7;
    
    /// The CWT Claims COSE header label (protected header 15).
    pub const CWT_CLAIMS_HEADER: i64 = 15;
}
