// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CoseSignTool CLI library.
//!
//! This library provides the core functionality for the CoseSignTool CLI,
//! including provider abstractions, output formatting, and command implementations.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod commands;
pub mod providers;