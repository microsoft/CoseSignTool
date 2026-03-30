// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

/// An X.509 Distinguished Name attribute
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct X509NameAttribute {
    /// The attribute label (e.g., "CN", "O", "C")
    pub label: String,
    
    /// The attribute value
    pub value: String,
}

impl X509NameAttribute {
    /// Create a new X.509 name attribute
    pub fn new(label: String, value: String) -> Self {
        Self { label, value }
    }
}

/// An X.509 Distinguished Name (DN)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct X509Name {
    /// The list of attributes in the DN
    pub attributes: Vec<X509NameAttribute>,
}

impl X509Name {
    /// Create a new X.509 name
    pub fn new(attributes: Vec<X509NameAttribute>) -> Self {
        Self { attributes }
    }

    /// Create an empty X.509 name
    pub fn empty() -> Self {
        Self {
            attributes: Vec::new(),
        }
    }

    /// Get the value of an attribute by label (case-insensitive)
    pub fn get_attribute(&self, label: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|attr| attr.label.eq_ignore_ascii_case(label))
            .map(|attr| attr.value.as_str())
    }

    /// Get the Common Name (CN) attribute value
    pub fn common_name(&self) -> Option<&str> {
        self.get_attribute("CN")
    }

    /// Get the Organization (O) attribute value
    pub fn organization(&self) -> Option<&str> {
        self.get_attribute("O")
    }

    /// Get the Country (C) attribute value
    pub fn country(&self) -> Option<&str> {
        self.get_attribute("C")
    }
}
