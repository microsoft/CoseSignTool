// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

use cosesign1_abstractions::ValidationResult;
use cosesign1_abstractions_ffi::cosesign1_abstractions_result as base_result;

extern "C" fn cb_read_fail(_ctx: *mut std::ffi::c_void, _out: *mut u8, _out_len: usize, bytes_read: *mut usize) -> i32 {
    unsafe {
        if !bytes_read.is_null() {
            *bytes_read = 0;
        }
    }
    1
}

extern "C" fn cb_seek_fail(_ctx: *mut std::ffi::c_void, _offset: i64, _origin: i32, new_pos: *mut u64) -> i32 {
    unsafe {
        if !new_pos.is_null() {
            *new_pos = 0;
        }
    }
    1
}

extern "C" fn cb_read_ok(_ctx: *mut std::ffi::c_void, _out: *mut u8, _out_len: usize, bytes_read: *mut usize) -> i32 {
    unsafe {
        if !bytes_read.is_null() {
            *bytes_read = 0;
        }
    }
    0
}

extern "C" fn cb_seek_ok(_ctx: *mut std::ffi::c_void, _offset: i64, _origin: i32, new_pos: *mut u64) -> i32 {
    unsafe {
        if !new_pos.is_null() {
            *new_pos = 0;
        }
    }
    0
}

fn encode_minimal_cose_sign1(payload: Option<&[u8]>) -> Vec<u8> {
    let mut protected_map = Vec::new();
    {
        let mut enc = minicbor::Encoder::new(&mut protected_map);
        enc.map(0).unwrap();
    }

    let mut out = Vec::new();
    let mut enc = minicbor::Encoder::new(&mut out);
    enc.array(4).unwrap();
    enc.bytes(&protected_map).unwrap();
    enc.map(0).unwrap();
    match payload {
        Some(p) => {
            enc.bytes(p).unwrap();
        }
        None => {
            enc.null().unwrap();
        }
    }
    enc.bytes(&[0u8; 64]).unwrap();
    out
}

#[test]
fn ffi_validation_functions_are_exercised_for_coverage() {
    unsafe {
        // Null-result getters.
        assert!(!cosesign1_validation_result_is_valid(std::ptr::null()));
        assert!(cosesign1_validation_result_validator_name(std::ptr::null()).is_null());
        assert_eq!(cosesign1_validation_result_failure_count(std::ptr::null()), 0);
        let fv = cosesign1_validation_result_failure_at(std::ptr::null(), 0);
        assert!(fv.message.is_null());
        assert!(fv.error_code.is_null());
        assert_eq!(cosesign1_validation_result_metadata_count(std::ptr::null()), 0);
        let kv = cosesign1_validation_result_metadata_at(std::ptr::null(), 0);
        assert!(kv.key.is_null());
        assert!(kv.value.is_null());

        // NULL_ARGUMENT.
        let res = cosesign1_validation_verify_signature(std::ptr::null(), 0, std::ptr::null(), 0, std::ptr::null(), 0);
        assert!(!cosesign1_validation_result_is_valid(res));
        cosesign1_validation_result_free(res);

        // CBOR_PARSE_ERROR.
        let bad = [0x01u8, 0x02u8, 0x03u8];
        let res = cosesign1_validation_verify_signature(bad.as_ptr(), bad.len(), std::ptr::null(), 0, std::ptr::null(), 0);
        assert!(!cosesign1_validation_result_is_valid(res));
        cosesign1_validation_result_free(res);

        // Detached payload: hit reader callback-missing branches.
        let cose_detached = encode_minimal_cose_sign1(None);
        let reader = cosesign1_reader {
            ctx: std::ptr::null_mut(),
            read: None,
            seek: None,
        };
        let res = cosesign1_validation_verify_signature_with_payload_reader(
            cose_detached.as_ptr(),
            cose_detached.len(),
            reader,
            std::ptr::null(),
            0,
        );
        assert!(!cosesign1_validation_result_is_valid(res));
        cosesign1_validation_result_free(res);

        // Exercise CallbackReader read/seek error branches directly.
        // read: missing callback
        let mut rdr = CallbackReader {
            r: cosesign1_reader {
                ctx: std::ptr::null_mut(),
                read: None,
                seek: Some(cb_seek_fail),
            },
        };
        assert!(std::io::Read::read(&mut rdr, &mut [0u8; 8]).is_err());

        // read: callback fails
        let mut rdr = CallbackReader {
            r: cosesign1_reader {
                ctx: std::ptr::null_mut(),
                read: Some(cb_read_fail),
                seek: Some(cb_seek_fail),
            },
        };
        assert!(std::io::Read::read(&mut rdr, &mut [0u8; 8]).is_err());

        // seek: missing callback
        let mut rdr = CallbackReader {
            r: cosesign1_reader {
                ctx: std::ptr::null_mut(),
                read: Some(cb_read_fail),
                seek: None,
            },
        };
        assert!(std::io::Seek::seek(&mut rdr, std::io::SeekFrom::Start(0)).is_err());

        // seek: callback fails for Start/Current/End (covers origin mapping)
        let mut rdr = CallbackReader {
            r: cosesign1_reader {
                ctx: std::ptr::null_mut(),
                read: Some(cb_read_fail),
                seek: Some(cb_seek_fail),
            },
        };
        assert!(std::io::Seek::seek(&mut rdr, std::io::SeekFrom::Start(0)).is_err());
        assert!(std::io::Seek::seek(&mut rdr, std::io::SeekFrom::Current(1)).is_err());
        assert!(std::io::Seek::seek(&mut rdr, std::io::SeekFrom::End(-1)).is_err());

        // read/seek success paths.
        let mut rdr = CallbackReader {
            r: cosesign1_reader {
                ctx: std::ptr::null_mut(),
                read: Some(cb_read_ok),
                seek: Some(cb_seek_ok),
            },
        };
        assert_eq!(std::io::Read::read(&mut rdr, &mut [0u8; 8]).unwrap(), 0);
        assert_eq!(std::io::Seek::seek(&mut rdr, std::io::SeekFrom::Start(0)).unwrap(), 0);
        assert_eq!(std::io::Seek::seek(&mut rdr, std::io::SeekFrom::Current(1)).unwrap(), 0);
        assert_eq!(std::io::Seek::seek(&mut rdr, std::io::SeekFrom::End(-1)).unwrap(), 0);

        // Embedded payload: drives verify path without reader.
        let cose_embedded = encode_minimal_cose_sign1(Some(b"p"));
        let res = cosesign1_validation_verify_signature(
            cose_embedded.as_ptr(),
            cose_embedded.len(),
            std::ptr::null(),
            0,
            std::ptr::null(),
            0,
        );
        assert!(!cosesign1_validation_result_is_valid(res));
        cosesign1_validation_result_free(res);

        // Exercise payload/public_key Option branches in the FFI wrapper.
        let cose_embedded = encode_minimal_cose_sign1(Some(b"p"));
        let payload = b"payload";
        let pk = b"pk";
        let res = cosesign1_validation_verify_signature(
            cose_embedded.as_ptr(),
            cose_embedded.len(),
            payload.as_ptr(),
            payload.len(),
            pk.as_ptr(),
            pk.len(),
        );
        assert!(!cosesign1_validation_result_is_valid(res));
        cosesign1_validation_result_free(res);

        let res = cosesign1_validation_verify_signature(
            cose_embedded.as_ptr(),
            cose_embedded.len(),
            payload.as_ptr(),
            payload.len(),
            std::ptr::null(),
            0,
        );
        assert!(!cosesign1_validation_result_is_valid(res));
        cosesign1_validation_result_free(res);

        let res = cosesign1_validation_verify_signature(
            cose_embedded.as_ptr(),
            cose_embedded.len(),
            std::ptr::null(),
            0,
            pk.as_ptr(),
            pk.len(),
        );
        assert!(!cosesign1_validation_result_is_valid(res));
        cosesign1_validation_result_free(res);

        // Free on null.
        cosesign1_validation_result_free(std::ptr::null_mut());

        // Non-null result getters + in-range and out-of-range accessors.
        let mut vr = ValidationResult::failure_message("Signature", "oops", Some("SOME_CODE".to_string()));
        vr.metadata.insert("k".to_string(), "v".to_string());
        let res = Box::into_raw(Box::new(base_result::from_validation_result(vr)));
        assert!(!res.is_null());
        assert!(!cosesign1_validation_result_validator_name(res).is_null());
        assert_eq!(cosesign1_validation_result_failure_count(res), 1);
        assert!(!cosesign1_validation_result_failure_at(res, 0).message.is_null());
        assert!(!cosesign1_validation_result_failure_at(res, 0).error_code.is_null());
        assert!(cosesign1_validation_result_failure_at(res, 999).message.is_null());
        assert_eq!(cosesign1_validation_result_metadata_count(res), 1);
        assert!(!cosesign1_validation_result_metadata_at(res, 0).key.is_null());
        assert!(!cosesign1_validation_result_metadata_at(res, 0).value.is_null());
        assert!(cosesign1_validation_result_metadata_at(res, 999).key.is_null());
        cosesign1_validation_result_free(res);

        // verify_signature_with_payload_reader parse error branch.
        let bad = [0xffu8];
        let reader = cosesign1_reader {
            ctx: std::ptr::null_mut(),
            read: None,
            seek: None,
        };
        let res = cosesign1_validation_verify_signature_with_payload_reader(
            bad.as_ptr(),
            bad.len(),
            reader,
            pk.as_ptr(),
            pk.len(),
        );
        assert!(!cosesign1_validation_result_is_valid(res));
        cosesign1_validation_result_free(res);
    }
}
