// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use did_x509::parsing::percent_encoding::{percent_encode, percent_decode};

#[test]
fn test_percent_encode_simple() {
    assert_eq!(percent_encode("hello"), "hello");
    assert_eq!(percent_encode("hello-world"), "hello-world");
    assert_eq!(percent_encode("hello_world"), "hello_world");
    assert_eq!(percent_encode("hello.world"), "hello.world");
}

#[test]
fn test_percent_encode_special() {
    assert_eq!(percent_encode("hello world"), "hello%20world");
    assert_eq!(percent_encode("hello:world"), "hello%3Aworld");
    assert_eq!(percent_encode("hello/world"), "hello%2Fworld");
}

#[test]
fn test_percent_encode_unicode() {
    assert_eq!(percent_encode("héllo"), "h%C3%A9llo");
    assert_eq!(percent_encode("世界"), "%E4%B8%96%E7%95%8C");
}

#[test]
fn test_percent_decode_simple() {
    assert_eq!(percent_decode("hello").unwrap(), "hello");
    assert_eq!(percent_decode("hello-world").unwrap(), "hello-world");
}

#[test]
fn test_percent_decode_special() {
    assert_eq!(percent_decode("hello%20world").unwrap(), "hello world");
    assert_eq!(percent_decode("hello%3Aworld").unwrap(), "hello:world");
    assert_eq!(percent_decode("hello%2Fworld").unwrap(), "hello/world");
}

#[test]
fn test_percent_decode_unicode() {
    assert_eq!(percent_decode("h%C3%A9llo").unwrap(), "héllo");
    assert_eq!(percent_decode("%E4%B8%96%E7%95%8C").unwrap(), "世界");
}

#[test]
fn test_roundtrip() {
    let test_cases = vec![
        "hello world",
        "test:value",
        "path/to/resource",
        "héllo wörld",
        "example@example.com",
        "CN=Test, O=Example",
    ];

    for input in test_cases {
        let encoded = percent_encode(input);
        let decoded = percent_decode(&encoded).unwrap();
        assert_eq!(input, decoded, "Roundtrip failed for: {}", input);
    }
}
