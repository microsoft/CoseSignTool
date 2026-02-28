// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wrapper around OpenSSL EVP_PKEY with automatic key type detection.

use openssl::pkey::{PKey, Private, Public};
use openssl::ec::EcKey;
use openssl::rsa::Rsa;

/// Key type enumeration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyType {
    Ec,
    Rsa,
    Ed25519,
    #[cfg(feature = "pqc")]
    MlDsa(MlDsaVariant),
}

/// ML-DSA algorithm variants (FIPS 204).
#[cfg(feature = "pqc")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlDsaVariant {
    MlDsa44,
    MlDsa65,
    MlDsa87,
}

#[cfg(feature = "pqc")]
impl MlDsaVariant {
    /// Returns the OpenSSL algorithm name for this variant.
    pub fn openssl_name(&self) -> &'static str {
        match self {
            MlDsaVariant::MlDsa44 => "ML-DSA-44",
            MlDsaVariant::MlDsa65 => "ML-DSA-65",
            MlDsaVariant::MlDsa87 => "ML-DSA-87",
        }
    }

    /// Returns the COSE algorithm identifier for this variant.
    pub fn cose_algorithm(&self) -> i64 {
        match self {
            MlDsaVariant::MlDsa44 => cose_primitives::ML_DSA_44,
            MlDsaVariant::MlDsa65 => cose_primitives::ML_DSA_65,
            MlDsaVariant::MlDsa87 => cose_primitives::ML_DSA_87,
        }
    }
}

/// Wrapper around OpenSSL private key with key type information.
pub struct EvpPrivateKey {
    pub(crate) pkey: PKey<Private>,
    pub(crate) key_type: KeyType,
}

impl EvpPrivateKey {
    /// Creates an EvpPrivateKey from an OpenSSL PKey, auto-detecting the key type.
    pub fn from_pkey(pkey: PKey<Private>) -> Result<Self, String> {
        let key_type = detect_key_type_private(&pkey)?;
        Ok(Self { pkey, key_type })
    }
    
    /// Creates an EvpPrivateKey from EC key.
    pub fn from_ec(ec_key: EcKey<Private>) -> Result<Self, String> {
        let pkey = PKey::from_ec_key(ec_key)
            .map_err(|e| format!("Failed to create PKey from EC key: {}", e))?;
        Ok(Self {
            pkey,
            key_type: KeyType::Ec,
        })
    }
    
    /// Creates an EvpPrivateKey from RSA key.
    pub fn from_rsa(rsa_key: Rsa<Private>) -> Result<Self, String> {
        let pkey = PKey::from_rsa(rsa_key)
            .map_err(|e| format!("Failed to create PKey from RSA key: {}", e))?;
        Ok(Self {
            pkey,
            key_type: KeyType::Rsa,
        })
    }
    
    /// Returns the key type.
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }
    
    /// Returns a reference to the underlying PKey.
    pub fn pkey(&self) -> &PKey<Private> {
        &self.pkey
    }

    /// Extracts the public key from this private key.
    pub fn public_key(&self) -> Result<EvpPublicKey, String> {
        // Serialize the public key portion
        let public_der = self.pkey
            .public_key_to_der()
            .map_err(|e| format!("Failed to serialize public key: {}", e))?;

        // Load it back as a public key
        let public_pkey = PKey::public_key_from_der(&public_der)
            .map_err(|e| format!("Failed to deserialize public key: {}", e))?;

        EvpPublicKey::from_pkey(public_pkey)
    }
}

/// Wrapper around OpenSSL public key with key type information.
pub struct EvpPublicKey {
    pub(crate) pkey: PKey<Public>,
    pub(crate) key_type: KeyType,
}

impl EvpPublicKey {
    /// Creates an EvpPublicKey from an OpenSSL PKey, auto-detecting the key type.
    pub fn from_pkey(pkey: PKey<Public>) -> Result<Self, String> {
        let key_type = detect_key_type_public(&pkey)?;
        Ok(Self { pkey, key_type })
    }
    
    /// Creates an EvpPublicKey from EC key.
    pub fn from_ec(ec_key: EcKey<Public>) -> Result<Self, String> {
        let pkey = PKey::from_ec_key(ec_key)
            .map_err(|e| format!("Failed to create PKey from EC key: {}", e))?;
        Ok(Self {
            pkey,
            key_type: KeyType::Ec,
        })
    }
    
    /// Creates an EvpPublicKey from RSA key.
    pub fn from_rsa(rsa_key: Rsa<Public>) -> Result<Self, String> {
        let pkey = PKey::from_rsa(rsa_key)
            .map_err(|e| format!("Failed to create PKey from RSA key: {}", e))?;
        Ok(Self {
            pkey,
            key_type: KeyType::Rsa,
        })
    }
    
    /// Returns the key type.
    pub fn key_type(&self) -> KeyType {
        self.key_type
    }
    
    /// Returns a reference to the underlying PKey.
    pub fn pkey(&self) -> &PKey<Public> {
        &self.pkey
    }
}

/// Detects the key type from a private key.
fn detect_key_type_private(pkey: &PKey<Private>) -> Result<KeyType, String> {
    if pkey.ec_key().is_ok() {
        Ok(KeyType::Ec)
    } else if pkey.rsa().is_ok() {
        Ok(KeyType::Rsa)
    } else if pkey.id() == openssl::pkey::Id::ED25519 {
        Ok(KeyType::Ed25519)
    } else {
        #[cfg(feature = "pqc")]
        {
            // Try ML-DSA detection using openssl-sys
            if let Some(variant) = detect_mldsa_variant(pkey) {
                return Ok(KeyType::MlDsa(variant));
            }
        }
        Err(format!("Unsupported key type: {:?}", pkey.id()))
    }
}

/// Detects the key type from a public key.
fn detect_key_type_public(pkey: &PKey<Public>) -> Result<KeyType, String> {
    if pkey.ec_key().is_ok() {
        Ok(KeyType::Ec)
    } else if pkey.rsa().is_ok() {
        Ok(KeyType::Rsa)
    } else if pkey.id() == openssl::pkey::Id::ED25519 {
        Ok(KeyType::Ed25519)
    } else {
        #[cfg(feature = "pqc")]
        {
            // Try ML-DSA detection using openssl-sys
            if let Some(variant) = detect_mldsa_variant(pkey) {
                return Ok(KeyType::MlDsa(variant));
            }
        }
        Err(format!("Unsupported key type: {:?}", pkey.id()))
    }
}

/// Detects ML-DSA variant using openssl-sys EVP_PKEY_is_a.
#[cfg(feature = "pqc")]
fn detect_mldsa_variant<T>(pkey: &PKey<T>) -> Option<MlDsaVariant> {
    use foreign_types::ForeignTypeRef;
    use std::ffi::CString;
    use std::os::raw::{c_char, c_int};

    // Declare EVP_PKEY_is_a from OpenSSL 3.x
    extern "C" {
        fn EVP_PKEY_is_a(pkey: *const openssl_sys::EVP_PKEY, keytype: *const c_char) -> c_int;
    }

    // Try each ML-DSA variant
    for variant in &[
        MlDsaVariant::MlDsa44,
        MlDsaVariant::MlDsa65,
        MlDsaVariant::MlDsa87,
    ] {
        let name = CString::new(variant.openssl_name()).ok()?;
        unsafe {
            let raw_pkey = pkey.as_ptr() as *const openssl_sys::EVP_PKEY;
            let result = EVP_PKEY_is_a(raw_pkey, name.as_ptr());
            if result == 1 {
                return Some(*variant);
            }
        }
    }
    None
}

/// Generates an ML-DSA key pair for the specified variant.
///
/// # Arguments
///
/// * `variant` - The ML-DSA variant to generate
///
/// # Returns
///
/// A private key for signing operations.
///
/// # Safety
///
/// Uses unsafe FFI to call EVP_PKEY_Q_keygen.
#[cfg(feature = "pqc")]
pub fn generate_mldsa_keypair(variant: MlDsaVariant) -> Result<EvpPrivateKey, String> {
    use foreign_types::ForeignType;
    use std::ffi::CString;
    use std::os::raw::c_char;
    use std::ptr;

    // Declare EVP_PKEY_Q_keygen from OpenSSL 3.x
    extern "C" {
        fn EVP_PKEY_Q_keygen(
            libctx: *mut openssl_sys::OSSL_LIB_CTX,
            propq: *const c_char,
            type_: *const c_char,
        ) -> *mut openssl_sys::EVP_PKEY;
    }

    let alg_name = CString::new(variant.openssl_name())
        .map_err(|e| format!("Invalid algorithm name: {}", e))?;

    let raw_pkey = unsafe {
        EVP_PKEY_Q_keygen(
            ptr::null_mut(), // library context (NULL = default)
            ptr::null(),     // property query (NULL = default)
            alg_name.as_ptr(),
        )
    };

    if raw_pkey.is_null() {
        return Err(format!(
            "Failed to generate {} keypair",
            variant.openssl_name()
        ));
    }

    // Wrap the raw pointer in a safe PKey
    let pkey = unsafe { PKey::from_ptr(raw_pkey) };

    Ok(EvpPrivateKey {
        pkey,
        key_type: KeyType::MlDsa(variant),
    })
}
