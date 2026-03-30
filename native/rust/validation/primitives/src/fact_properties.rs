// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::borrow::Cow;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactValue<'a> {
    Bool(bool),
    Str(Cow<'a, str>),
    Usize(usize),
    U32(u32),
    I64(i64),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FactValueOwned {
    Bool(bool),
    String(String),
    Usize(usize),
    U32(u32),
    I64(i64),
}

impl FactValueOwned {
    /// Convert this owned value into a borrowed view.
    ///
    /// This is used when comparing owned expected values against facts that expose borrowed
    /// property values.
    pub fn as_borrowed(&self) -> FactValue<'_> {
        match self {
            FactValueOwned::Bool(v) => FactValue::Bool(*v),
            FactValueOwned::String(v) => FactValue::Str(Cow::Borrowed(v.as_str())),
            FactValueOwned::Usize(v) => FactValue::Usize(*v),
            FactValueOwned::U32(v) => FactValue::U32(*v),
            FactValueOwned::I64(v) => FactValue::I64(*v),
        }
    }
}

/// Exposes a fact's fields by *name*.
///
/// This is the core hook that allows trust policies to be expressed declaratively (property + value)
/// without requiring callers to write Rust closures.
pub trait FactProperties {
    /// Return a property value by name.
    ///
    /// Implementations should return `None` for unknown properties. Callers use this method to
    /// evaluate declarative policies without requiring a custom Rust closure per fact type.
    fn get_property<'a>(&'a self, name: &str) -> Option<FactValue<'a>>;
}
