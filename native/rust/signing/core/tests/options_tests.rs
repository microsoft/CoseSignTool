// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for signing options.

use cose_sign1_signing::SigningOptions;

#[test]
fn test_signing_options_default() {
    let options = SigningOptions::default();

    assert!(options.additional_header_contributors.is_empty());
    assert!(options.additional_data.is_none());
    assert!(!options.disable_transparency);
    assert!(!options.fail_on_transparency_error);
    assert!(options.embed_payload);
}

#[test]
fn test_signing_options_with_additional_data() {
    let mut options = SigningOptions::default();
    options.additional_data = Some(vec![1, 2, 3, 4]);

    assert_eq!(options.additional_data, Some(vec![1, 2, 3, 4]));
}

#[test]
fn test_signing_options_transparency_flags() {
    let mut options = SigningOptions::default();
    options.disable_transparency = true;
    options.fail_on_transparency_error = true;

    assert!(options.disable_transparency);
    assert!(options.fail_on_transparency_error);
}

#[test]
fn test_signing_options_embed_payload() {
    let mut options = SigningOptions::default();
    assert!(options.embed_payload); // default is true

    options.embed_payload = false;
    assert!(!options.embed_payload);
}

#[test]
fn test_signing_options_clone() {
    let mut options = SigningOptions::default();
    options.additional_data = Some(vec![5, 6, 7]);
    options.disable_transparency = true;

    let cloned = options.clone();
    assert_eq!(cloned.additional_data, Some(vec![5, 6, 7]));
    assert!(cloned.disable_transparency);
}
