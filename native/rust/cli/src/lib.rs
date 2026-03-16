// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

//! CoseSignTool CLI library.
//!
//! This library provides the core functionality for the CoseSignTool CLI,
//! including provider abstractions, output formatting, and command implementations.


pub mod commands;
pub mod providers;
