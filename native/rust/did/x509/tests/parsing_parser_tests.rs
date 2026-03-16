// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use did_x509::parsing::{is_valid_oid, is_valid_base64url};

#[test]
fn test_is_valid_oid() {
    assert!(is_valid_oid("1.2.3.4"));
    assert!(is_valid_oid("2.5.4.3"));
    assert!(is_valid_oid("1.3.6.1.4.1.57264.1.1"));
    
    assert!(!is_valid_oid("1"));
    assert!(!is_valid_oid("1."));
    assert!(!is_valid_oid(".1.2"));
    assert!(!is_valid_oid("1.2.a"));
    assert!(!is_valid_oid(""));
}

#[test]
fn test_is_valid_base64url() {
    assert!(is_valid_base64url("abc123"));
    assert!(is_valid_base64url("abc-123_def"));
    assert!(is_valid_base64url("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"));
    
    assert!(!is_valid_base64url("abc+123"));
    assert!(!is_valid_base64url("abc/123"));
    assert!(!is_valid_base64url("abc=123"));
}
