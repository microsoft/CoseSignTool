// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// DID:x509 method prefix
pub const DID_PREFIX: &str = "did:x509";

/// Full DID:x509 prefix with version
pub const FULL_DID_PREFIX: &str = "did:x509:0";

/// Current DID:x509 version
pub const VERSION: &str = "0";

/// Separator between CA fingerprint and policies
pub const POLICY_SEPARATOR: &str = "::";

/// Separator within DID components
pub const VALUE_SEPARATOR: &str = ":";

/// Hash algorithm constants
pub const HASH_ALGORITHM_SHA256: &str = "sha256";
pub const HASH_ALGORITHM_SHA384: &str = "sha384";
pub const HASH_ALGORITHM_SHA512: &str = "sha512";

/// Policy name constants
pub const POLICY_SUBJECT: &str = "subject";
pub const POLICY_SAN: &str = "san";
pub const POLICY_EKU: &str = "eku";
pub const POLICY_FULCIO_ISSUER: &str = "fulcio-issuer";

/// SAN (Subject Alternative Name) type constants
pub const SAN_TYPE_EMAIL: &str = "email";
pub const SAN_TYPE_DNS: &str = "dns";
pub const SAN_TYPE_URI: &str = "uri";
pub const SAN_TYPE_DN: &str = "dn";

/// Well-known OID constants
pub const OID_COMMON_NAME: &str = "2.5.4.3";
pub const OID_LOCALITY: &str = "2.5.4.7";
pub const OID_STATE: &str = "2.5.4.8";
pub const OID_ORGANIZATION: &str = "2.5.4.10";
pub const OID_ORGANIZATIONAL_UNIT: &str = "2.5.4.11";
pub const OID_COUNTRY: &str = "2.5.4.6";
pub const OID_STREET: &str = "2.5.4.9";
pub const OID_FULCIO_ISSUER: &str = "1.3.6.1.4.1.57264.1.1";
pub const OID_EXTENDED_KEY_USAGE: &str = "2.5.29.37";
pub const OID_SAN: &str = "2.5.29.17";
pub const OID_BASIC_CONSTRAINTS: &str = "2.5.29.19";

/// X.509 attribute labels
pub const ATTRIBUTE_CN: &str = "CN";
pub const ATTRIBUTE_L: &str = "L";
pub const ATTRIBUTE_ST: &str = "ST";
pub const ATTRIBUTE_O: &str = "O";
pub const ATTRIBUTE_OU: &str = "OU";
pub const ATTRIBUTE_C: &str = "C";
pub const ATTRIBUTE_STREET: &str = "STREET";

/// Map OID to attribute label
pub fn oid_to_attribute_label(oid: &str) -> Option<&'static str> {
    match oid {
        OID_COMMON_NAME => Some(ATTRIBUTE_CN),
        OID_LOCALITY => Some(ATTRIBUTE_L),
        OID_STATE => Some(ATTRIBUTE_ST),
        OID_ORGANIZATION => Some(ATTRIBUTE_O),
        OID_ORGANIZATIONAL_UNIT => Some(ATTRIBUTE_OU),
        OID_COUNTRY => Some(ATTRIBUTE_C),
        OID_STREET => Some(ATTRIBUTE_STREET),
        _ => None,
    }
}

/// Map attribute label to OID
pub fn attribute_label_to_oid(label: &str) -> Option<&'static str> {
    match label.to_uppercase().as_str() {
        ATTRIBUTE_CN => Some(OID_COMMON_NAME),
        ATTRIBUTE_L => Some(OID_LOCALITY),
        ATTRIBUTE_ST => Some(OID_STATE),
        ATTRIBUTE_O => Some(OID_ORGANIZATION),
        ATTRIBUTE_OU => Some(OID_ORGANIZATIONAL_UNIT),
        ATTRIBUTE_C => Some(OID_COUNTRY),
        ATTRIBUTE_STREET => Some(OID_STREET),
        _ => None,
    }
}
