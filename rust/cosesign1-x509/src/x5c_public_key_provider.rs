// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cosesign1_abstractions::ParsedCoseSign1;
use cosesign1_abstractions::{
    PublicKeyProviderError, ResolvedSigningKey, SigningKeyProvider, SigningKeyProviderRegistration,
};

use crate::x5c_header::extract_x5c_certs_der;

struct X5cPublicKeyProvider;

impl SigningKeyProvider for X5cPublicKeyProvider {
    fn name(&self) -> &'static str {
        "x5c"
    }

    fn try_resolve_signing_key(
        &self,
        parsed: &ParsedCoseSign1,
    ) -> Result<Option<ResolvedSigningKey>, PublicKeyProviderError> {
        let Some(certs_der) = extract_x5c_certs_der(parsed) else {
            return Ok(None);
        };

        let certs_der = certs_der.map_err(PublicKeyProviderError::Message)?;

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
