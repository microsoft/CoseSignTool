// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Direct signature factory module.
//!
//! Provides factory for creating COSE_Sign1 messages with direct signatures
//! (embedded or detached payload).

mod content_type_contributor;
mod factory;
mod options;

pub use content_type_contributor::ContentTypeHeaderContributor;
pub use factory::DirectSignatureFactory;
pub use options::DirectSignatureOptions;
