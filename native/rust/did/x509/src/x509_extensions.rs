// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::constants::*;
use crate::error::DidX509Error;
use std::borrow::Cow;
use x509_parser::prelude::*;

/// Extract Extended Key Usage OIDs from a certificate
pub fn extract_extended_key_usage(cert: &X509Certificate) -> Vec<Cow<'static, str>> {
    let mut ekus = Vec::new();

    for ext in cert.extensions() {
        if ext.oid.to_id_string() == OID_EXTENDED_KEY_USAGE {
            if let ParsedExtension::ExtendedKeyUsage(eku) = ext.parsed_extension() {
                // Add standard EKU OIDs
                if eku.server_auth {
                    ekus.push(Cow::Borrowed("1.3.6.1.5.5.7.3.1"));
                }
                if eku.client_auth {
                    ekus.push(Cow::Borrowed("1.3.6.1.5.5.7.3.2"));
                }
                if eku.code_signing {
                    ekus.push(Cow::Borrowed("1.3.6.1.5.5.7.3.3"));
                }
                if eku.email_protection {
                    ekus.push(Cow::Borrowed("1.3.6.1.5.5.7.3.4"));
                }
                if eku.time_stamping {
                    ekus.push(Cow::Borrowed("1.3.6.1.5.5.7.3.8"));
                }
                if eku.ocsp_signing {
                    ekus.push(Cow::Borrowed("1.3.6.1.5.5.7.3.9"));
                }

                // Add other/custom OIDs
                for oid in &eku.other {
                    ekus.push(Cow::Owned(oid.to_id_string()));
                }
            }
        }
    }

    ekus
}

/// Extract EKU OIDs from a certificate (alias for builder convenience)
pub fn extract_eku_oids(cert: &X509Certificate) -> Result<Vec<Cow<'static, str>>, DidX509Error> {
    let oids = extract_extended_key_usage(cert);
    Ok(oids)
}

/// Check if a certificate is a CA certificate
pub fn is_ca_certificate(cert: &X509Certificate) -> bool {
    for ext in cert.extensions() {
        if ext.oid.to_id_string() == OID_BASIC_CONSTRAINTS {
            if let ParsedExtension::BasicConstraints(bc) = ext.parsed_extension() {
                return bc.ca;
            }
        }
    }
    false
}

/// Extract Fulcio issuer from certificate extensions
pub fn extract_fulcio_issuer(cert: &X509Certificate) -> Option<String> {
    for ext in cert.extensions() {
        if ext.oid.to_id_string() == OID_FULCIO_ISSUER {
            // The value is DER-encoded, typically an OCTET STRING containing UTF-8 text
            // This is a simplified extraction - production code would properly parse DER
            if let Ok(s) = std::str::from_utf8(ext.value) {
                return Some(s.to_string());
            }
        }
    }
    None
}
