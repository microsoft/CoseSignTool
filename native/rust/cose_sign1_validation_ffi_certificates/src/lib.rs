//! X.509 certificates pack FFI bindings.
//!
//! This crate exposes the X.509 certificate validation pack to C/C++ consumers.

#![deny(unsafe_op_in_unsafe_fn)]

use cose_sign1_validation_certificates::facts::{
    X509ChainElementIdentityFact, X509ChainElementValidityFact, X509ChainTrustedFact,
    X509PublicKeyAlgorithmFact, X509SigningCertificateIdentityFact,
};
use cose_sign1_validation_certificates::fluent_ext::{
    PrimarySigningKeyScopeRulesExt, X509SigningCertificateIdentityWhereExt,
    X509ChainElementIdentityWhereExt, X509ChainElementValidityWhereExt, X509ChainTrustedWhereExt,
    X509PublicKeyAlgorithmWhereExt,
};
use cose_sign1_validation_certificates::pack::{CertificateTrustOptions, X509CertificateTrustPack};
use cose_sign1_validation_ffi::{
    cose_status_t, cose_trust_policy_builder_t, cose_validator_builder_t, with_catch_unwind,
    with_trust_policy_builder_mut,
};
use std::ffi::{c_char, CStr};
use std::sync::Arc;

fn string_from_ptr(arg_name: &'static str, s: *const c_char) -> Result<String, anyhow::Error> {
    if s.is_null() {
        anyhow::bail!("{arg_name} must not be null");
    }
    let s = unsafe { CStr::from_ptr(s) }
        .to_str()
        .map_err(|_| anyhow::anyhow!("{arg_name} must be valid UTF-8"))?;
    Ok(s.to_string())
}

/// C ABI representation of certificate trust options.
#[repr(C)]
pub struct cose_certificate_trust_options_t {
    /// If true, treat a well-formed embedded x5chain as trusted (deterministic, for tests/pinned roots).
    pub trust_embedded_chain_as_trusted: bool,
    
    /// If true, enable identity pinning based on allowed_thumbprints.
    pub identity_pinning_enabled: bool,
    
    /// Null-terminated array of allowed certificate thumbprint strings (case/whitespace insensitive).
    /// NULL pointer means no thumbprint filtering.
    pub allowed_thumbprints: *const *const c_char,
    
    /// Null-terminated array of PQC algorithm OID strings.
    /// NULL pointer means no custom PQC OIDs.
    pub pqc_algorithm_oids: *const *const c_char,
}

/// Helper to convert null-terminated string array to Vec<String>.
unsafe fn string_array_to_vec(arr: *const *const c_char) -> Vec<String> {
    if arr.is_null() {
        return Vec::new();
    }
    
    let mut result = Vec::new();
    let mut ptr = arr;
    loop {
        let s = unsafe { *ptr };
        if s.is_null() {
            break;
        }
        if let Ok(cstr) = unsafe { CStr::from_ptr(s).to_str() } {
            result.push(cstr.to_string());
        }
        ptr = unsafe { ptr.add(1) };
    }
    result
}

/// Adds the X.509 certificates trust pack with default options.
#[no_mangle]
pub extern "C" fn cose_validator_builder_with_certificates_pack(
    builder: *mut cose_validator_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;
        builder
            .packs
            .push(Arc::new(X509CertificateTrustPack::default()));
        Ok(cose_status_t::COSE_OK)
    })
}

/// Adds the X.509 certificates trust pack with custom options.
#[no_mangle]
pub extern "C" fn cose_validator_builder_with_certificates_pack_ex(
    builder: *mut cose_validator_builder_t,
    options: *const cose_certificate_trust_options_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        let builder = unsafe { builder.as_mut() }
            .ok_or_else(|| anyhow::anyhow!("builder must not be null"))?;
        
        let opts = if options.is_null() {
            CertificateTrustOptions::default()
        } else {
            let opts_ref = unsafe { &*options };
            CertificateTrustOptions {
                trust_embedded_chain_as_trusted: opts_ref.trust_embedded_chain_as_trusted,
                identity_pinning_enabled: opts_ref.identity_pinning_enabled,
                allowed_thumbprints: unsafe { string_array_to_vec(opts_ref.allowed_thumbprints) },
                pqc_algorithm_oids: unsafe { string_array_to_vec(opts_ref.pqc_algorithm_oids) },
            }
        };
        
        builder
            .packs
            .push(Arc::new(X509CertificateTrustPack::new(opts)));
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the X.509 chain is trusted.
///
/// This API is provided by the certificates pack FFI library and extends `cose_trust_policy_builder_t`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_x509_chain_trusted(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| s.require_x509_chain_trusted())
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the X.509 chain is not trusted.
///
/// This API is provided by the certificates pack FFI library and extends `cose_trust_policy_builder_t`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_x509_chain_not_trusted(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509ChainTrustedFact>(|w| w.require_not_trusted())
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the X.509 chain could be built (pack observed at least one element).
///
/// This API is provided by the certificates pack FFI library and extends `cose_trust_policy_builder_t`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_x509_chain_built(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509ChainTrustedFact>(|w| w.require_chain_built())
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the X.509 chain could not be built.
///
/// This API is provided by the certificates pack FFI library and extends `cose_trust_policy_builder_t`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_x509_chain_not_built(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509ChainTrustedFact>(|w| w.require_chain_not_built())
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the X.509 chain element count equals `expected`.
///
/// This API is provided by the certificates pack FFI library and extends `cose_trust_policy_builder_t`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_x509_chain_element_count_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    expected: usize,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509ChainTrustedFact>(|w| w.element_count_eq(expected))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the X.509 chain status flags equal `expected`.
///
/// This API is provided by the certificates pack FFI library and extends `cose_trust_policy_builder_t`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_x509_chain_status_flags_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    expected: u32,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509ChainTrustedFact>(|w| w.status_flags_eq(expected))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the leaf chain element (index 0) has a non-empty thumbprint.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_leaf_chain_thumbprint_present(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| s.require_leaf_chain_thumbprint_present())
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that a signing certificate identity fact is present.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_signing_certificate_present(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| s.require_signing_certificate_present())
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: pin the leaf certificate subject name (chain element index 0).
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_leaf_subject_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    subject_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let subject = string_from_ptr("subject_utf8", subject_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| s.require_leaf_subject_eq(subject))
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: pin the issuer certificate subject name (chain element index 1).
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_issuer_subject_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    subject_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let subject = string_from_ptr("subject_utf8", subject_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| s.require_issuer_subject_eq(subject))
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the signing certificate subject/issuer matches the leaf chain element.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_signing_certificate_subject_issuer_matches_leaf_chain_element(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require_signing_certificate_subject_issuer_matches_leaf_chain_element()
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: if the issuer element (index 1) is missing, allow; otherwise require issuer chaining.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_leaf_issuer_is_next_chain_subject_optional(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| s.require_leaf_issuer_is_next_chain_subject_optional())
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require the leaf signing certificate thumbprint to equal the provided value.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_signing_certificate_thumbprint_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    thumbprint_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let thumbprint = string_from_ptr("thumbprint_utf8", thumbprint_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509SigningCertificateIdentityFact>(|w| w.thumbprint_eq(thumbprint))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the leaf signing certificate thumbprint is present and non-empty.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_signing_certificate_thumbprint_present(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509SigningCertificateIdentityFact>(|w| w.thumbprint_non_empty())
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require the leaf signing certificate subject to equal the provided value.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_signing_certificate_subject_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    subject_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let subject = string_from_ptr("subject_utf8", subject_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509SigningCertificateIdentityFact>(|w| w.subject_eq(subject))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require the leaf signing certificate issuer to equal the provided value.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_signing_certificate_issuer_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    issuer_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let issuer = string_from_ptr("issuer_utf8", issuer_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509SigningCertificateIdentityFact>(|w| w.issuer_eq(issuer))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require the leaf signing certificate serial number to equal the provided value.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_signing_certificate_serial_number_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    serial_number_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let serial_number = string_from_ptr("serial_number_utf8", serial_number_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509SigningCertificateIdentityFact>(|w| w.serial_number_eq(serial_number))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the signing certificate is expired at or before `now_unix_seconds`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_signing_certificate_expired_at_or_before(
    policy_builder: *mut cose_trust_policy_builder_t,
    now_unix_seconds: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509SigningCertificateIdentityFact>(|w| w.cert_expired_at_or_before(now_unix_seconds))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the leaf signing certificate is valid at `now_unix_seconds`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_signing_certificate_valid_at(
    policy_builder: *mut cose_trust_policy_builder_t,
    now_unix_seconds: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509SigningCertificateIdentityFact>(|w| w.cert_valid_at(now_unix_seconds))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require signing certificate `not_before <= max_unix_seconds`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_signing_certificate_not_before_le(
    policy_builder: *mut cose_trust_policy_builder_t,
    max_unix_seconds: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509SigningCertificateIdentityFact>(|w| w.not_before_le(max_unix_seconds))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require signing certificate `not_before >= min_unix_seconds`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_signing_certificate_not_before_ge(
    policy_builder: *mut cose_trust_policy_builder_t,
    min_unix_seconds: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509SigningCertificateIdentityFact>(|w| w.not_before_ge(min_unix_seconds))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require signing certificate `not_after <= max_unix_seconds`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_signing_certificate_not_after_le(
    policy_builder: *mut cose_trust_policy_builder_t,
    max_unix_seconds: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509SigningCertificateIdentityFact>(|w| w.not_after_le(max_unix_seconds))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require signing certificate `not_after >= min_unix_seconds`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_signing_certificate_not_after_ge(
    policy_builder: *mut cose_trust_policy_builder_t,
    min_unix_seconds: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509SigningCertificateIdentityFact>(|w| w.not_after_ge(min_unix_seconds))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the X.509 chain element at `index` has subject equal to the provided value.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_chain_element_subject_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    index: usize,
    subject_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let subject = string_from_ptr("subject_utf8", subject_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509ChainElementIdentityFact>(|w| w.index_eq(index).subject_eq(subject))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the X.509 chain element at `index` has issuer equal to the provided value.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_chain_element_issuer_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    index: usize,
    issuer_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let issuer = string_from_ptr("issuer_utf8", issuer_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509ChainElementIdentityFact>(|w| w.index_eq(index).issuer_eq(issuer))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the X.509 chain element at `index` has thumbprint equal to the provided value.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_chain_element_thumbprint_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    index: usize,
    thumbprint_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let thumbprint = string_from_ptr("thumbprint_utf8", thumbprint_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509ChainElementIdentityFact>(|w| w.index_eq(index).thumbprint_eq(thumbprint))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the X.509 chain element at `index` has a non-empty thumbprint.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_chain_element_thumbprint_present(
    policy_builder: *mut cose_trust_policy_builder_t,
    index: usize,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509ChainElementIdentityFact>(|w| w.index_eq(index).thumbprint_non_empty())
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the X.509 chain element at `index` is valid at `now_unix_seconds`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_chain_element_valid_at(
    policy_builder: *mut cose_trust_policy_builder_t,
    index: usize,
    now_unix_seconds: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509ChainElementValidityFact>(|w| w.index_eq(index).cert_valid_at(now_unix_seconds))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require chain element `not_before <= max_unix_seconds`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_chain_element_not_before_le(
    policy_builder: *mut cose_trust_policy_builder_t,
    index: usize,
    max_unix_seconds: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509ChainElementValidityFact>(|w| w.index_eq(index).not_before_le(max_unix_seconds))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require chain element `not_before >= min_unix_seconds`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_chain_element_not_before_ge(
    policy_builder: *mut cose_trust_policy_builder_t,
    index: usize,
    min_unix_seconds: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509ChainElementValidityFact>(|w| w.index_eq(index).not_before_ge(min_unix_seconds))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require chain element `not_after <= max_unix_seconds`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_chain_element_not_after_le(
    policy_builder: *mut cose_trust_policy_builder_t,
    index: usize,
    max_unix_seconds: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509ChainElementValidityFact>(|w| w.index_eq(index).not_after_le(max_unix_seconds))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require chain element `not_after >= min_unix_seconds`.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_chain_element_not_after_ge(
    policy_builder: *mut cose_trust_policy_builder_t,
    index: usize,
    min_unix_seconds: i64,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509ChainElementValidityFact>(|w| w.index_eq(index).not_after_ge(min_unix_seconds))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: deny if a PQC algorithm is explicitly detected; allow if missing.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_not_pqc_algorithm_or_missing(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| s.require_not_pqc_algorithm_or_missing())
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the X.509 public key algorithm fact has thumbprint equal to the provided value.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_thumbprint_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    thumbprint_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let thumbprint = string_from_ptr("thumbprint_utf8", thumbprint_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509PublicKeyAlgorithmFact>(|w| w.thumbprint_eq(thumbprint))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the X.509 public key algorithm OID equals the provided value.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_oid_eq(
    policy_builder: *mut cose_trust_policy_builder_t,
    oid_utf8: *const c_char,
) -> cose_status_t {
    with_catch_unwind(|| {
        let oid = string_from_ptr("oid_utf8", oid_utf8)?;
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509PublicKeyAlgorithmFact>(|w| w.algorithm_oid_eq(oid))
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the X.509 public key algorithm is flagged as PQC.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_is_pqc(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509PublicKeyAlgorithmFact>(|w| w.require_pqc())
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}

/// Trust-policy helper: require that the X.509 public key algorithm is not flagged as PQC.
#[no_mangle]
pub extern "C" fn cose_certificates_trust_policy_builder_require_x509_public_key_algorithm_is_not_pqc(
    policy_builder: *mut cose_trust_policy_builder_t,
) -> cose_status_t {
    with_catch_unwind(|| {
        with_trust_policy_builder_mut(policy_builder, |b| {
            b.for_primary_signing_key(|s| {
                s.require::<X509PublicKeyAlgorithmFact>(|w| w.require_not_pqc())
            })
        })?;
        Ok(cose_status_t::COSE_OK)
    })
}
