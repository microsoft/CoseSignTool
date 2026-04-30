// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CoseSignTool Plugin API — shared traits and IPC protocol.
//!
//! This crate defines the contract between the CoseSignTool host process and
//! external plugin binaries. Plugins are subprocess-isolated: they run in their
//! own OS process and communicate with the host via named pipes using a
//! JSON-framed request/response protocol.
//!
//! # Security Model
//!
//! - **Process isolation**: Plugins cannot access host memory or credentials.
//! - **Explicit capability declaration**: Plugins declare what they provide.
//! - **Key material stays in-plugin**: Private keys never cross the pipe.
//! - **OS-level access control**: Named pipes support ACLs.
//!
//! # Plugin Binary Contract
//!
//! A plugin binary must:
//! 1. Accept `--pipe-name <name>` argument (or create its own and print to stdout)
//! 2. Listen on the named pipe for JSON-framed requests
//! 3. Respond to each request with a JSON-framed response
//! 4. Exit cleanly on `shutdown` request or when the pipe closes

pub mod protocol;
pub mod traits;
