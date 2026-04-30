// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Output formatting for CLI results.

use std::io::Write;

/// Print the CoseSignTool banner to stderr.
pub fn print_banner() {
    let version = env!("CARGO_PKG_VERSION");
    let separator = "=".repeat(80);
    eprintln!("{separator}");
    eprintln!("CoseSignTool (Rust)");
    eprintln!("  Version: {version}");
    eprintln!("{separator}");
    eprintln!();
}

/// Output format for command results.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
pub enum OutputFormat {
    Text,
    Json,
    Quiet,
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self::Text
    }
}

/// Write a key-value pair in the appropriate format.
pub fn write_field(w: &mut dyn Write, key: &str, value: &str) -> std::io::Result<()> {
    writeln!(w, "  {key}: {value}")
}

/// Write a section header.
pub fn write_section(w: &mut dyn Write, title: &str) -> std::io::Result<()> {
    writeln!(w, "\n{title}")?;
    writeln!(w, "{}", "-".repeat(title.len()))
}
