// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Output formatters for CLI results.
//!
//! Maps V2 C# `IOutputFormatter` with `TextOutputFormatter`, `JsonOutputFormatter`,
//! `XmlOutputFormatter`, `QuietOutputFormatter`.

use std::collections::BTreeMap;

/// A section of key-value output.
pub type OutputSection = BTreeMap<String, String>;

/// Format for CLI output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Quiet,
}

impl std::str::FromStr for OutputFormat {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "text" => Ok(Self::Text),
            "json" => Ok(Self::Json),
            "quiet" => Ok(Self::Quiet),
            other => Err(format!("Unknown output format: {}", other)),
        }
    }
}

/// Render structured output in the selected format.
pub fn render(format: OutputFormat, sections: &[(String, OutputSection)]) -> String {
    match format {
        OutputFormat::Text => render_text(sections),
        OutputFormat::Json => render_json(sections),
        OutputFormat::Quiet => String::new(),
    }
}

fn render_text(sections: &[(String, OutputSection)]) -> String {
    let mut out = String::new();
    for (name, section) in sections {
        out.push_str(name);
        out.push('\n');
        for (key, value) in section {
            out.push_str(&format!("  {}: {}\n", key, value));
        }
    }
    out
}

fn render_json(sections: &[(String, OutputSection)]) -> String {
    let map: BTreeMap<&str, &OutputSection> = sections.iter().map(|(k, v)| (k.as_str(), v)).collect();
    serde_json::to_string_pretty(&map).unwrap_or_default()
}