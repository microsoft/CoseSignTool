// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::models::SubjectAlternativeName;
use x509_parser::prelude::*;

/// Parse Subject Alternative Names from an X.509 certificate extension
pub fn parse_san_extension(extension: &X509Extension) -> Result<Vec<SubjectAlternativeName>, String> {
    if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
        let mut result = Vec::new();
        
        for general_name in &san.general_names {
            match general_name {
                GeneralName::RFC822Name(email) => {
                    result.push(SubjectAlternativeName::email(email.to_string()));
                }
                GeneralName::DNSName(dns) => {
                    result.push(SubjectAlternativeName::dns(dns.to_string()));
                }
                GeneralName::URI(uri) => {
                    result.push(SubjectAlternativeName::uri(uri.to_string()));
                }
                GeneralName::DirectoryName(name) => {
                    // Convert the X509Name to a string representation
                    result.push(SubjectAlternativeName::dn(format!("{}", name)));
                }
                _ => {
                    // Ignore other types for now
                }
            }
        }
        
        Ok(result)
    } else {
        Err("Extension is not a SubjectAlternativeName".to_string())
    }
}

/// Parse SANs from a certificate
pub fn parse_sans_from_certificate(cert: &X509Certificate) -> Vec<SubjectAlternativeName> {
    let mut sans = Vec::new();
    
    for ext in cert.extensions() {
        if let Ok(parsed_sans) = parse_san_extension(ext) {
            sans.extend(parsed_sans);
        }
    }
    
    sans
}
