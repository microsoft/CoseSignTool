// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CoseSignTool Plugin Loader — trusted bridge between host and compiled-in providers.

mod providers;

use anyhow::{Context, Result};
use cosesigntool_plugin_api::server;
use providers::{available_plugins, create_provider};

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    if let Err(err) = run() {
        eprintln!("[plugin-loader] fatal: {err:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|arg| arg == "--help" || arg == "-h") {
        print_help();
        return Ok(());
    }

    let plugin_name =
        find_arg(&args, "--plugin").context("--plugin is required (e.g., aas, akv)")?;
    let plugin = create_provider(plugin_name.as_str())?;
    server::run(plugin)?;
    Ok(())
}

fn print_help() {
    let available_plugins = available_plugins();
    let available_plugins = if available_plugins.is_empty() {
        "none".to_string()
    } else {
        available_plugins.join(", ")
    };

    println!(
        "CoseSignTool plugin loader\n\nUsage:\n  cosesigntool-plugin-loader --plugin <name> --pipe-name <name>\n\nOptions:\n  --plugin <name>       Compiled-in plugin name to host\n  --pipe-name <name>    Named pipe or Unix socket path to listen on\n  -h, --help            Show this help message\n\nAvailable plugins: {}",
        available_plugins
    );
}

fn find_arg(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|argument| argument == name)
        .and_then(|index| args.get(index + 1))
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::{available_plugins, create_provider, find_arg, print_help};
    use std::path::PathBuf;
    use std::process::Command;

    #[test]
    fn find_arg_returns_the_value_following_a_flag() {
        let args = vec![
            "loader".to_string(),
            "--plugin".to_string(),
            "local".to_string(),
            "--pipe-name".to_string(),
            "pipe-name".to_string(),
        ];

        assert_eq!(find_arg(&args, "--plugin"), Some("local".to_string()));
        assert_eq!(find_arg(&args, "--pipe-name"), Some("pipe-name".to_string()));
        assert_eq!(find_arg(&args, "--missing"), None);
    }

    #[test]
    fn find_arg_returns_none_when_flag_is_last_element() {
        let args = vec!["loader".to_string(), "--plugin".to_string()];
        assert_eq!(find_arg(&args, "--plugin"), None);
    }

    #[test]
    fn find_arg_returns_none_for_empty_args() {
        let args: Vec<String> = Vec::new();
        assert_eq!(find_arg(&args, "--plugin"), None);
    }

    #[test]
    fn available_plugins_returns_a_vec() {
        // With --features all, some plugins may be registered.
        // Just verify the function doesn't panic and returns a valid list.
        let plugins = available_plugins();
        // Each plugin name should be non-empty
        for name in &plugins {
            assert!(!name.is_empty());
        }
    }

    #[test]
    fn create_provider_unknown_name_returns_error() {
        let result = create_provider("nonexistent");
        match result {
            Err(err) => {
                let msg = format!("{:#}", err);
                assert!(msg.contains("Unknown plugin"));
                assert!(msg.contains("nonexistent"));
            }
            Ok(_) => panic!("expected error for unknown plugin name"),
        }
    }

    #[test]
    fn create_provider_empty_name_returns_error() {
        assert!(create_provider("").is_err());
    }

    #[test]
    fn print_help_does_not_panic() {
        // Just ensure it doesn't panic; output goes to stdout
        print_help();
    }

    #[test]
    fn plugin_loader_binary_exists_and_help_succeeds() {
        let workspace_root = workspace_root();
        let build_output = Command::new("cargo")
            .args([
                "build",
                "--quiet",
                "-p",
                "cosesigntool_plugin_loader",
                "--bin",
                "cosesigntool-plugin-loader",
            ])
            .current_dir(&workspace_root)
            .output()
            .expect("cargo build should execute");
        assert!(
            build_output.status.success(),
            "cargo build should succeed: {build_output:?}"
        );

        let binary_path = loader_binary_path();
        assert!(binary_path.exists(), "binary should exist at {}", binary_path.display());

        let output = Command::new(&binary_path)
            .arg("--help")
            .output()
            .expect("help command should execute");

        assert!(output.status.success(), "help should succeed: {output:?}");

        let stdout = String::from_utf8(output.stdout).expect("help output should be UTF-8");
        assert!(stdout.contains("CoseSignTool plugin loader"));
        assert!(stdout.contains("--plugin <name>"));
        assert!(stdout.contains("--pipe-name <name>"));
    }

    fn loader_binary_path() -> PathBuf {
        workspace_root().join("target").join("debug").join(if cfg!(windows) {
            "cosesigntool-plugin-loader.exe"
        } else {
            "cosesigntool-plugin-loader"
        })
    }

    fn workspace_root() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("package directory should have a parent")
            .parent()
            .expect("CLI directory should have a parent")
            .to_path_buf()
    }
}
