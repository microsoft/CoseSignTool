// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Indirect signature factory module.
//!
//! Provides factory for creating COSE_Sign1 messages with indirect signatures
//! (signs hash of payload instead of payload itself).

mod factory;
mod hash_envelope_contributor;
mod options;

pub use factory::IndirectSignatureFactory;
pub use hash_envelope_contributor::HashEnvelopeHeaderContributor;
pub use options::{HashAlgorithm, IndirectSignatureOptions};
