use cosesign1_common::{parse_cose_sign1, HeaderValue, ParsedCoseSign1};
use cosesign1_validation::{verify_parsed_cose_sign1, ValidationResult, VerifyOptions};

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum X509TrustMode {
    System = 0,
    CustomRoots = 1,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum X509RevocationMode {
    NoCheck = 0,
    Online = 1,
    Offline = 2,
}

#[derive(Debug, Clone)]
pub struct X509ChainVerifyOptions {
    pub trust_mode: X509TrustMode,
    pub revocation_mode: X509RevocationMode,
    pub trusted_roots_der: Vec<Vec<u8>>,
    pub allow_untrusted_roots: bool,
}

impl Default for X509ChainVerifyOptions {
    fn default() -> Self {
        Self {
            trust_mode: X509TrustMode::System,
            revocation_mode: X509RevocationMode::Online,
            trusted_roots_der: Vec::new(),
            allow_untrusted_roots: false,
        }
    }
}

pub fn verify_cose_sign1_with_x5c(
    validator_name: &str,
    cose_sign1: &[u8],
    options: &VerifyOptions,
    chain_options: Option<&X509ChainVerifyOptions>,
) -> ValidationResult {
    let parsed = match parse_cose_sign1(cose_sign1) {
        Ok(p) => p,
        Err(e) => return ValidationResult::failure_message(validator_name, e, Some("COSE_PARSE_ERROR".to_string())),
    };

    verify_parsed_cose_sign1_with_x5c(validator_name, &parsed, options, chain_options)
}

pub fn verify_parsed_cose_sign1_with_x5c(
    validator_name: &str,
    parsed: &ParsedCoseSign1,
    options: &VerifyOptions,
    chain_options: Option<&X509ChainVerifyOptions>,
) -> ValidationResult {
    // x5c header label is 33.
    let x5c = parsed
        .protected_headers
        .get_array(33)
        .or_else(|| parsed.unprotected_headers.get_array(33));

    let Some(x5c) = x5c else {
        return ValidationResult::failure_message(validator_name, "missing x5c header", Some("MISSING_X5C".to_string()));
    };

    let mut certs_der = Vec::new();
    for v in x5c {
        match v {
            HeaderValue::Bytes(b) => certs_der.push(b.clone()),
            _ => return ValidationResult::failure_message(validator_name, "x5c must be array of bstr", Some("X5C_TYPE_ERROR".to_string())),
        }
    }

    let Some(leaf_der) = certs_der.first() else {
        return ValidationResult::failure_message(validator_name, "x5c is empty", Some("X5C_EMPTY".to_string()));
    };

    match chain_options {
        Some(chain) => {
            if chain.revocation_mode != X509RevocationMode::NoCheck {
                return ValidationResult::failure_message(
                    validator_name,
                    "revocation checking not implemented in Rust yet",
                    Some("REVOCATION_UNSUPPORTED".to_string()),
                );
            }

            // Parity note: full X.509 path building + trust evaluation is not implemented yet.
            // We only support allow_untrusted_roots=true as a diagnostic mode for now.
            if !chain.allow_untrusted_roots {
                return ValidationResult::failure_message(
                    validator_name,
                    "X.509 chain trust evaluation not implemented in Rust yet",
                    Some("CHAIN_VERIFY_UNSUPPORTED".to_string()),
                );
            }
        }
        None => {}
    }

    let mut opts = options.clone();
    opts.public_key_bytes = Some(leaf_der.clone());

    let external = options.external_payload.as_deref().or_else(|| parsed.payload.as_deref());
    verify_parsed_cose_sign1(validator_name, parsed, external, &opts)
}
