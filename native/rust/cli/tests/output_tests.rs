// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for CLI output formatting.

use cose_sign1_cli::providers::output::{OutputFormat, render, OutputSection};
use std::collections::BTreeMap;

#[test]
fn test_output_format_from_str_valid() {
    assert_eq!("text".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
    assert_eq!("json".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
    assert_eq!("quiet".parse::<OutputFormat>().unwrap(), OutputFormat::Quiet);
    
    // Test case insensitive
    assert_eq!("TEXT".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
    assert_eq!("JSON".parse::<OutputFormat>().unwrap(), OutputFormat::Json);
    assert_eq!("QUIET".parse::<OutputFormat>().unwrap(), OutputFormat::Quiet);
    assert_eq!("Text".parse::<OutputFormat>().unwrap(), OutputFormat::Text);
}

#[test]
fn test_output_format_from_str_invalid() {
    let result = "xml".parse::<OutputFormat>();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Unknown output format: xml");
    
    let result = "invalid".parse::<OutputFormat>();
    assert!(result.is_err());
    assert_eq!(result.unwrap_err(), "Unknown output format: invalid");
}

#[test]
fn test_render_text_format() {
    let mut section1 = BTreeMap::new();
    section1.insert("key1".to_string(), "value1".to_string());
    section1.insert("key2".to_string(), "value2".to_string());
    
    let mut section2 = BTreeMap::new();
    section2.insert("keyA".to_string(), "valueA".to_string());
    
    let sections = vec![
        ("Section 1".to_string(), section1),
        ("Section 2".to_string(), section2),
    ];
    
    let result = render(OutputFormat::Text, &sections);
    assert!(result.contains("Section 1\n"));
    assert!(result.contains("  key1: value1\n"));
    assert!(result.contains("  key2: value2\n"));
    assert!(result.contains("Section 2\n"));
    assert!(result.contains("  keyA: valueA\n"));
}

#[test]
fn test_render_json_format() {
    let mut section1 = BTreeMap::new();
    section1.insert("key1".to_string(), "value1".to_string());
    section1.insert("key2".to_string(), "value2".to_string());
    
    let sections = vec![
        ("Section 1".to_string(), section1),
    ];
    
    let result = render(OutputFormat::Json, &sections);
    assert!(result.contains("\"Section 1\""));
    assert!(result.contains("\"key1\": \"value1\""));
    assert!(result.contains("\"key2\": \"value2\""));
    
    // Should be valid JSON
    let _: serde_json::Value = serde_json::from_str(&result).expect("Should be valid JSON");
}

#[test]
fn test_render_quiet_format() {
    let mut section1 = BTreeMap::new();
    section1.insert("key1".to_string(), "value1".to_string());
    
    let sections = vec![
        ("Section 1".to_string(), section1),
    ];
    
    let result = render(OutputFormat::Quiet, &sections);
    assert_eq!(result, "");
}

#[test]
fn test_render_empty_sections() {
    let sections: Vec<(String, OutputSection)> = vec![];
    
    assert_eq!(render(OutputFormat::Text, &sections), "");
    assert_eq!(render(OutputFormat::Json, &sections), "{}");
    assert_eq!(render(OutputFormat::Quiet, &sections), "");
}

#[test]
fn test_render_empty_section() {
    let empty_section = BTreeMap::new();
    let sections = vec![
        ("Empty Section".to_string(), empty_section),
    ];
    
    let result = render(OutputFormat::Text, &sections);
    assert_eq!(result, "Empty Section\n");
    
    let result = render(OutputFormat::Json, &sections);
    assert!(result.contains("\"Empty Section\": {}"));
}
