// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesign1_abstractions::ValidationResult;
use cosesign1_abstractions_ffi::cosesign1_abstractions_result as base_result;

use cosesign1_validation::*;

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
fn ffi_validation_smoke_covers_result_helpers_and_api_error_paths() {
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
        let bad = [0x01u8, 0x02u8, 0x03u8];
        let reader = cosesign1_reader {
            ctx: std::ptr::null_mut(),
            read: None,
            seek: None,
        };
        let res = cosesign1_validation_verify_signature_with_payload_reader(
            bad.as_ptr(),
            bad.len(),
            reader,
            std::ptr::null(),
            0,
        );
        assert!(!cosesign1_validation_result_is_valid(res));
        cosesign1_validation_result_free(res);
    }
}
