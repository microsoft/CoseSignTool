mod helpers;

use cose_openssl::EvpKey;
use cose_openssl::cose_verify1;
use helpers::*;

/// Free a buffer previously returned by `cose_sign` / `cose_sign_detached`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cose_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            drop(Vec::from_raw_parts(ptr, len, len));
        }
    }
}

/// Sign with embedded payload.
///
/// Produces a complete COSE_Sign1 envelope (tag 18).
///
/// * `phdr`    - serialised CBOR map (protected header, **without** alg).
/// * `uhdr`    - serialised CBOR map (unprotected header).
/// * `payload` - raw payload bytes.
/// * `key_der` - DER-encoded private key.
/// * `out_ptr` / `out_len` - on success, receives the COSE_Sign1 bytes
///   (caller must free with `cose_free`).
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cose_sign(
    phdr_ptr: *const u8,
    phdr_len: usize,
    uhdr_ptr: *const u8,
    uhdr_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    key_der_ptr: *const u8,
    key_der_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    unsafe {
        sign_inner(
            phdr_ptr,
            phdr_len,
            uhdr_ptr,
            uhdr_len,
            payload_ptr,
            payload_len,
            key_der_ptr,
            key_der_len,
            out_ptr,
            out_len,
            false,
        )
    }
}

/// Sign with detached payload.
///
/// Same as `cose_sign` but the COSE_Sign1 envelope carries a CBOR null
/// instead of the payload (the payload must be supplied separately at
/// verification time).
///
/// Returns 0 on success, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cose_sign_detached(
    phdr_ptr: *const u8,
    phdr_len: usize,
    uhdr_ptr: *const u8,
    uhdr_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    key_der_ptr: *const u8,
    key_der_len: usize,
    out_ptr: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    unsafe {
        sign_inner(
            phdr_ptr,
            phdr_len,
            uhdr_ptr,
            uhdr_len,
            payload_ptr,
            payload_len,
            key_der_ptr,
            key_der_len,
            out_ptr,
            out_len,
            true,
        )
    }
}

/// Verify a COSE_Sign1 envelope with embedded payload.
///
/// * `envelope` - the full COSE_Sign1 bytes.
/// * `key_der`  - DER-encoded public key (SubjectPublicKeyInfo).
///
/// Returns 1 if the signature is valid, 0 if invalid, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cose_verify(
    envelope_ptr: *const u8,
    envelope_len: usize,
    key_der_ptr: *const u8,
    key_der_len: usize,
) -> i32 {
    unsafe {
        let key =
            match EvpKey::from_der_public(as_slice(key_der_ptr, key_der_len)) {
                Ok(k) => k,
                Err(_) => return -1,
            };

        match cose_verify1(&key, as_slice(envelope_ptr, envelope_len), None) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(_) => -1,
        }
    }
}

/// Verify a COSE_Sign1 envelope with a detached payload.
///
/// * `envelope` - the COSE_Sign1 bytes (payload slot is CBOR null).
/// * `payload`  - the detached payload bytes.
/// * `key_der`  - DER-encoded public key (SubjectPublicKeyInfo).
///
/// Returns 1 if the signature is valid, 0 if invalid, -1 on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn cose_verify_detached(
    envelope_ptr: *const u8,
    envelope_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    key_der_ptr: *const u8,
    key_der_len: usize,
) -> i32 {
    unsafe {
        let key =
            match EvpKey::from_der_public(as_slice(key_der_ptr, key_der_len)) {
                Ok(k) => k,
                Err(_) => return -1,
            };

        match cose_verify1(
            &key,
            as_slice(envelope_ptr, envelope_len),
            Some(as_slice(payload_ptr, payload_len)),
        ) {
            Ok(true) => 1,
            Ok(false) => 0,
            Err(_) => -1,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cose_openssl::{KeyType, WhichEC};
    use std::ptr;

    const TEST_PHDR: &str = "A319018B020FA3061A698B72820173736572766963652E6578616D706C652E636F6D02706C65646765722E7369676E6174757265666363662E7631A1647478696465322E313334";

    /// Helper: generate a key pair, return (priv_der, pub_der).
    fn make_key_pair(typ: KeyType) -> (Vec<u8>, Vec<u8>) {
        let key = EvpKey::new(typ).unwrap();
        let priv_der = key.to_der_private().unwrap();
        let pub_der = key.to_der_public().unwrap();
        (priv_der, pub_der)
    }

    #[test]
    fn ffi_sign_verify_ec() {
        let (priv_der, pub_der) = make_key_pair(KeyType::EC(WhichEC::P256));
        let phdr = hex::decode(TEST_PHDR).unwrap();
        let uhdr = b"\xa0";
        let payload = b"ffi roundtrip";

        let mut out_ptr: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;

        let rc = unsafe {
            cose_sign(
                phdr.as_ptr(),
                phdr.len(),
                uhdr.as_ptr(),
                uhdr.len(),
                payload.as_ptr(),
                payload.len(),
                priv_der.as_ptr(),
                priv_der.len(),
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(rc, 0);
        assert!(!out_ptr.is_null());
        assert!(out_len > 0);

        let rc = unsafe {
            cose_verify(out_ptr, out_len, pub_der.as_ptr(), pub_der.len())
        };
        assert_eq!(rc, 1);

        unsafe { cose_free(out_ptr, out_len) };
    }

    #[test]
    fn ffi_sign_detached_verify_detached_ec() {
        let (priv_der, pub_der) = make_key_pair(KeyType::EC(WhichEC::P384));
        let phdr = hex::decode(TEST_PHDR).unwrap();
        let uhdr = b"\xa0";
        let payload = b"detached ffi";

        let mut out_ptr: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;

        let rc = unsafe {
            cose_sign_detached(
                phdr.as_ptr(),
                phdr.len(),
                uhdr.as_ptr(),
                uhdr.len(),
                payload.as_ptr(),
                payload.len(),
                priv_der.as_ptr(),
                priv_der.len(),
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(rc, 0);

        // Verify with detached payload.
        let rc = unsafe {
            cose_verify_detached(
                out_ptr,
                out_len,
                payload.as_ptr(),
                payload.len(),
                pub_der.as_ptr(),
                pub_der.len(),
            )
        };
        assert_eq!(rc, 1);

        // Non-detached verify must fail (payload slot is null).
        let rc = unsafe {
            cose_verify(out_ptr, out_len, pub_der.as_ptr(), pub_der.len())
        };
        assert_eq!(rc, -1);

        unsafe { cose_free(out_ptr, out_len) };
    }

    #[test]
    fn ffi_verify_wrong_key_returns_zero() {
        let (priv_der, _) = make_key_pair(KeyType::EC(WhichEC::P256));
        let (_, other_pub) = make_key_pair(KeyType::EC(WhichEC::P256));
        let phdr = hex::decode(TEST_PHDR).unwrap();
        let uhdr = b"\xa0";
        let payload = b"wrong key";

        let mut out_ptr: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;

        let rc = unsafe {
            cose_sign(
                phdr.as_ptr(),
                phdr.len(),
                uhdr.as_ptr(),
                uhdr.len(),
                payload.as_ptr(),
                payload.len(),
                priv_der.as_ptr(),
                priv_der.len(),
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(rc, 0);

        // Verify with a different public key -- signature invalid.
        let rc = unsafe {
            cose_verify(out_ptr, out_len, other_pub.as_ptr(), other_pub.len())
        };
        assert_eq!(rc, 0);

        unsafe { cose_free(out_ptr, out_len) };
    }

    #[test]
    fn ffi_sign_bad_key_returns_error() {
        let phdr = hex::decode(TEST_PHDR).unwrap();
        let uhdr = b"\xa0";
        let payload = b"bad key";
        let garbage_key = [0xde, 0xad, 0xbe, 0xef];

        let mut out_ptr: *mut u8 = ptr::null_mut();
        let mut out_len: usize = 0;

        let rc = unsafe {
            cose_sign(
                phdr.as_ptr(),
                phdr.len(),
                uhdr.as_ptr(),
                uhdr.len(),
                payload.as_ptr(),
                payload.len(),
                garbage_key.as_ptr(),
                garbage_key.len(),
                &mut out_ptr,
                &mut out_len,
            )
        };
        assert_eq!(rc, -1);
    }

    #[cfg(feature = "pqc")]
    mod pqc_tests {
        use super::*;
        use cose_openssl::WhichMLDSA;

        #[test]
        fn ffi_sign_verify_mldsa() {
            let (priv_der, pub_der) =
                make_key_pair(KeyType::MLDSA(WhichMLDSA::P65));
            let phdr = hex::decode(TEST_PHDR).unwrap();
            let uhdr = b"\xa0";
            let payload = b"mldsa ffi roundtrip";

            let mut out_ptr: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;

            let rc = unsafe {
                cose_sign(
                    phdr.as_ptr(),
                    phdr.len(),
                    uhdr.as_ptr(),
                    uhdr.len(),
                    payload.as_ptr(),
                    payload.len(),
                    priv_der.as_ptr(),
                    priv_der.len(),
                    &mut out_ptr,
                    &mut out_len,
                )
            };
            assert_eq!(rc, 0);

            let rc = unsafe {
                cose_verify(out_ptr, out_len, pub_der.as_ptr(), pub_der.len())
            };
            assert_eq!(rc, 1);

            unsafe { cose_free(out_ptr, out_len) };
        }

        #[test]
        fn ffi_sign_detached_verify_detached_mldsa() {
            let (priv_der, pub_der) =
                make_key_pair(KeyType::MLDSA(WhichMLDSA::P44));
            let phdr = hex::decode(TEST_PHDR).unwrap();
            let uhdr = b"\xa0";
            let payload = b"mldsa detached ffi";

            let mut out_ptr: *mut u8 = ptr::null_mut();
            let mut out_len: usize = 0;

            let rc = unsafe {
                cose_sign_detached(
                    phdr.as_ptr(),
                    phdr.len(),
                    uhdr.as_ptr(),
                    uhdr.len(),
                    payload.as_ptr(),
                    payload.len(),
                    priv_der.as_ptr(),
                    priv_der.len(),
                    &mut out_ptr,
                    &mut out_len,
                )
            };
            assert_eq!(rc, 0);

            let rc = unsafe {
                cose_verify_detached(
                    out_ptr,
                    out_len,
                    payload.as_ptr(),
                    payload.len(),
                    pub_der.as_ptr(),
                    pub_der.len(),
                )
            };
            assert_eq!(rc, 1);

            unsafe { cose_free(out_ptr, out_len) };
        }
    }
}
