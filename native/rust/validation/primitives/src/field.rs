// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::marker::PhantomData;

/// A strongly typed handle to a fact property.
///
/// This is intentionally minimal: it only carries the property name plus type information,
/// allowing policy builders to expose compile-time checked "allowed fields".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Field<TFact, TValue> {
    pub(crate) name: &'static str,
    _phantom: PhantomData<fn() -> (TFact, TValue)>,
}

impl<TFact, TValue> Field<TFact, TValue> {
    /// Create a new field handle for a named property.
    ///
    /// The name must match what the fact exposes via [`crate::fact_properties::FactProperties`].
    pub const fn new(name: &'static str) -> Self {
        Self {
            name,
            _phantom: PhantomData,
        }
    }

    /// Return the canonical property name.
    pub fn name(&self) -> &'static str {
        self.name
    }
}
