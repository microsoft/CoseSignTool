// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::CoseAlgorithm;

#[derive(Default, Clone)]
pub struct VerifyOptions {
    /// External payload bytes.
    pub external_payload: Option<Vec<u8>>,
    /// Public key input bytes.
    pub public_key_bytes: Option<Vec<u8>>,
    /// If set, verification fails unless the COSE `alg` header equals this value.
    pub expected_alg: Option<CoseAlgorithm>,
}
