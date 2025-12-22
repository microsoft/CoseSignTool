// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesign1_abstractions::{HeaderValue, ParsedCoseSign1};
use cosesign1_abstractions::{
    PublicKeyProviderError, ResolvedSigningKey, SigningKeyProvider, SigningKeyProviderRegistration,
};

struct X5cPublicKeyProvider;

impl SigningKeyProvider for X5cPublicKeyProvider {
    fn name(&self) -> &'static str {
        "x5c"
    }

    fn try_resolve_signing_key(
        &self,
        parsed: &ParsedCoseSign1,
    ) -> Result<Option<ResolvedSigningKey>, PublicKeyProviderError> {
        // x5c header label is 33.
        // COSE allows headers to be in protected or unprotected maps.
        let x5c = parsed
            .protected_headers
            .get_array(33)
            .or_else(|| parsed.unprotected_headers.get_array(33));

        let Some(x5c) = x5c else {
            return Ok(None);
        };

        // x5c must be an array of bstr elements.
        let mut certs_der: Vec<Vec<u8>> = Vec::new();
        for v in x5c {
            match v {
                HeaderValue::Bytes(b) => certs_der.push(b.clone()),
                _ => {
                    return Err(PublicKeyProviderError::Message(
                        "x5c must be array of bstr".to_string(),
                    ))
                }
            }
        }

        let Some(leaf_der) = certs_der.first() else {
            return Err(PublicKeyProviderError::Message("x5c is empty".to_string()));
        };

        if leaf_der.is_empty() {
            return Err(PublicKeyProviderError::Message(
                "x5c leaf certificate bytes were empty".to_string(),
            ));
        }

        // Return the leaf certificate DER bytes. The core validator accepts DER cert bytes.
        // Return the leaf certificate DER bytes. The core validator accepts DER cert bytes.
        // We do not perform trust validation here; that is handled by message validators.
        Ok(Some(ResolvedSigningKey::with_material(
            leaf_der.clone(),
            Box::new(certs_der),
        )))
    }
}

static PROVIDER: X5cPublicKeyProvider = X5cPublicKeyProvider;

inventory::submit! {
    SigningKeyProviderRegistration {
        id: crate::X5C_PROVIDER_ID,
        name: crate::X5C_PROVIDER_NAME,
        // Prefer x5c over other future providers by default.
        priority: 100,
        provider: &PROVIDER,
    }
}
