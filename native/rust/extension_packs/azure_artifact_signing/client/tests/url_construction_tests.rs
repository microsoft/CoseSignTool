// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use azure_artifact_signing_client::{CertificateProfileClientOptions, API_VERSION};

#[test]
fn test_sign_url() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account",
        "my-profile",
    );

    let expected = "https://eus.codesigning.azure.net/codesigningaccounts/my-account/certificateprofiles/my-profile/sign?api-version=2022-06-15-preview";
    let actual = format!("{}/sign?api-version={}", opts.base_url(), opts.api_version);
    assert_eq!(actual, expected);
}

#[test]
fn test_eku_url() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account",
        "my-profile",
    );

    let expected = "https://eus.codesigning.azure.net/codesigningaccounts/my-account/certificateprofiles/my-profile/sign/eku?api-version=2022-06-15-preview";
    let actual = format!(
        "{}/sign/eku?api-version={}",
        opts.base_url(),
        opts.api_version
    );
    assert_eq!(actual, expected);
}

#[test]
fn test_rootcert_url() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account",
        "my-profile",
    );

    let expected = "https://eus.codesigning.azure.net/codesigningaccounts/my-account/certificateprofiles/my-profile/sign/rootcert?api-version=2022-06-15-preview";
    let actual = format!(
        "{}/sign/rootcert?api-version={}",
        opts.base_url(),
        opts.api_version
    );
    assert_eq!(actual, expected);
}

#[test]
fn test_certchain_url() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account",
        "my-profile",
    );

    let expected = "https://eus.codesigning.azure.net/codesigningaccounts/my-account/certificateprofiles/my-profile/sign/certchain?api-version=2022-06-15-preview";
    let actual = format!(
        "{}/sign/certchain?api-version={}",
        opts.base_url(),
        opts.api_version
    );
    assert_eq!(actual, expected);
}

#[test]
fn test_operation_poll_url() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account",
        "my-profile",
    );

    let operation_id = "op-12345-67890";
    let expected = "https://eus.codesigning.azure.net/codesigningaccounts/my-account/certificateprofiles/my-profile/sign/op-12345-67890?api-version=2022-06-15-preview";
    let actual = format!(
        "{}/sign/{}?api-version={}",
        opts.base_url(),
        operation_id,
        opts.api_version
    );
    assert_eq!(actual, expected);
}

#[test]
fn test_all_url_patterns_with_different_regions() {
    let regions = vec![
        "https://eus.codesigning.azure.net",
        "https://weu.codesigning.azure.net",
        "https://neu.codesigning.azure.net",
        "https://scus.codesigning.azure.net",
    ];

    for region in regions {
        let opts = CertificateProfileClientOptions::new(region, "test-account", "test-profile");
        let base_url = opts.base_url();
        let api_version = &opts.api_version;

        // Test sign URL
        let sign_url = format!("{}/sign?api-version={}", base_url, api_version);
        assert!(sign_url.starts_with(region.trim_end_matches('/')));
        assert!(sign_url.contains("/codesigningaccounts/test-account"));
        assert!(sign_url.contains("/certificateprofiles/test-profile"));
        assert!(sign_url.contains("/sign?"));
        assert!(sign_url.contains("api-version=2022-06-15-preview"));

        // Test EKU URL
        let eku_url = format!("{}/sign/eku?api-version={}", base_url, api_version);
        assert!(eku_url.contains("/sign/eku?"));

        // Test rootcert URL
        let rootcert_url = format!("{}/sign/rootcert?api-version={}", base_url, api_version);
        assert!(rootcert_url.contains("/sign/rootcert?"));

        // Test certchain URL
        let certchain_url = format!("{}/sign/certchain?api-version={}", base_url, api_version);
        assert!(certchain_url.contains("/sign/certchain?"));

        // Test operation poll URL
        let poll_url = format!("{}/sign/test-op-id?api-version={}", base_url, api_version);
        assert!(poll_url.contains("/sign/test-op-id?"));
    }
}

#[test]
fn test_url_construction_with_special_characters() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "account-with-dashes",
        "profile_with_underscores.and.dots",
    );

    let base_url = opts.base_url();
    assert_eq!(base_url, "https://eus.codesigning.azure.net/codesigningaccounts/account-with-dashes/certificateprofiles/profile_with_underscores.and.dots");

    // Test that all URL patterns work with special characters
    let sign_url = format!("{}/sign?api-version={}", base_url, opts.api_version);
    assert!(sign_url.contains("account-with-dashes"));
    assert!(sign_url.contains("profile_with_underscores.and.dots"));

    let operation_url = format!(
        "{}/sign/op-123-456?api-version={}",
        base_url, opts.api_version
    );
    assert!(operation_url.contains("/sign/op-123-456?"));
}

#[test]
fn test_api_version_consistency() {
    let opts = CertificateProfileClientOptions::new(
        "https://eus.codesigning.azure.net",
        "my-account",
        "my-profile",
    );

    // All URLs should use the same API version
    let expected_version = "api-version=2022-06-15-preview";

    let sign_url = format!("{}/sign?api-version={}", opts.base_url(), opts.api_version);
    assert!(sign_url.contains(expected_version));

    let eku_url = format!(
        "{}/sign/eku?api-version={}",
        opts.base_url(),
        opts.api_version
    );
    assert!(eku_url.contains(expected_version));

    let rootcert_url = format!(
        "{}/sign/rootcert?api-version={}",
        opts.base_url(),
        opts.api_version
    );
    assert!(rootcert_url.contains(expected_version));

    let certchain_url = format!(
        "{}/sign/certchain?api-version={}",
        opts.base_url(),
        opts.api_version
    );
    assert!(certchain_url.contains(expected_version));

    let poll_url = format!(
        "{}/sign/op-id?api-version={}",
        opts.base_url(),
        opts.api_version
    );
    assert!(poll_url.contains(expected_version));

    // Verify against the constant
    assert_eq!(opts.api_version, API_VERSION);
}

#[test]
fn test_endpoint_trimming_in_url_construction() {
    // Test that URL construction handles trailing slashes correctly
    let test_cases = vec![
        "https://eus.codesigning.azure.net",
        "https://eus.codesigning.azure.net/",
        "https://eus.codesigning.azure.net//",
    ];

    for endpoint in test_cases {
        let opts = CertificateProfileClientOptions::new(endpoint, "acc", "prof");
        let base_url = opts.base_url();

        // All should produce the same base URL (no double slashes)
        assert_eq!(
            base_url,
            "https://eus.codesigning.azure.net/codesigningaccounts/acc/certificateprofiles/prof"
        );

        // Test a complete URL
        let complete_url = format!("{}/sign?api-version={}", base_url, opts.api_version);
        assert_eq!(complete_url, "https://eus.codesigning.azure.net/codesigningaccounts/acc/certificateprofiles/prof/sign?api-version=2022-06-15-preview");

        // Should not contain double slashes (except in protocol)
        let url_without_protocol = complete_url.replace("https://", "");
        assert!(!url_without_protocol.contains("//"));
    }
}
