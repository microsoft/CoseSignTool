// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CoseSignTool Plugin API — shared traits and IPC protocol.
//!
//! This crate defines the contract between the CoseSignTool host process and
//! external plugin binaries. Plugins are subprocess-isolated: they run in their
//! own OS process and communicate with the host via named pipes using a
//! CBOR-framed request/response protocol.
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
//! 1. Accept `--mode pipe --pipe-name <name>` arguments
//! 2. Create and listen on the named pipe identified by `<name>`
//! 3. Read 4-byte big-endian length-prefixed CBOR requests from the pipe
//! 4. Write 4-byte big-endian length-prefixed CBOR responses to the pipe
//! 5. Exit cleanly on `shutdown` request or when the pipe closes

pub mod protocol;
pub mod traits;
