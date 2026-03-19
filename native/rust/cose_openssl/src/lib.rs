// Partner-contributed crate — allow certain clippy lints to avoid
// modifying upstream code unnecessarily.
#![allow(
    clippy::mut_from_ref,
    clippy::len_without_is_empty,
    clippy::useless_format
)]

mod cbor;
mod cose;
mod ossl_wrappers;
mod sign;
mod verify;

pub use cbor::CborValue;
pub use cose::{cose_sign1, cose_verify1};
pub use ossl_wrappers::{EvpKey, KeyType, WhichEC, WhichRSA};

#[cfg(feature = "pqc")]
pub use ossl_wrappers::WhichMLDSA;
