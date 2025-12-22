// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Opaque options payload passed across crate boundaries.

use std::any::Any;

/// Opaque options passed across crate boundaries.
///
/// `cosesign1` stays decoupled from concrete option types owned by plugins.
pub struct OpaqueOptions(Box<dyn Any + Send + Sync>);

impl OpaqueOptions {
    pub fn new<T: Any + Send + Sync>(value: T) -> Self {
        Self(Box::new(value))
    }

    pub fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self.0.as_ref()
    }
}
