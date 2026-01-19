// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use cose_sign1_validation::fluent::CoseSign1;
use cose_sign1_validation_transparent_mst::pack::MstTrustPack;
use cose_sign1_validation_transparent_mst::receipt_verify::{
    verify_mst_receipt, ReceiptVerifyInput,
};
use std::fs;
use std::path::PathBuf;

const MST_RECEIPT_HEADER_LABEL: i64 = 394;

fn scitt_testdata_path(file_name: &str) -> PathBuf {
    // Prefer local testdata if present, else fall back to the certificates crate test vectors.
    let local = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("cose_sign1_validation")
        .join("testdata")
        .join("v1")
        .join(file_name);
    if local.exists() {
        return local;
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("cose_sign1_validation_certificates")
        .join("testdata")
        .join("v1")
        .join(file_name)
}

fn read_receipts_from_unprotected_header(cose_bytes: &[u8]) -> Vec<Vec<u8>> {
    let msg = CoseSign1::from_cbor(cose_bytes).expect("valid COSE_Sign1");

    let mut d = tinycbor::Decoder(msg.unprotected_header.as_ref());
    let mut map = d.map_visitor().expect("unprotected header must be a map");

    while let Some(entry) = map.visit::<i64, tinycbor::Any<'_>>() {
        let (k, v_any) = entry.expect("map entry decode failed");
        if k != MST_RECEIPT_HEADER_LABEL {
            continue;
        }

        let mut vd = tinycbor::Decoder(v_any.as_ref());
        let mut arr = vd.array_visitor().expect("receipts must be an array");

        let mut receipts = Vec::new();
        while let Some(item) = arr.visit::<&[u8]>() {
            let b = item.expect("receipt item decode failed");
            receipts.push(b.to_vec());
        }

        return receipts;
    }

    Vec::new()
}

fn main() {
    let pack = MstTrustPack {
        allow_network: true,
        offline_jwks_json: None,
        jwks_api_version: None,
    };

    for file in ["1ts-statement.scitt", "2ts-statement.scitt"] {
        let path = scitt_testdata_path(file);
        let cose_bytes = fs::read(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));

        println!("== {file} ==");
        let receipts = read_receipts_from_unprotected_header(cose_bytes.as_slice());
        println!("receipts: {}", receipts.len());

        for (i, receipt_bytes) in receipts.iter().enumerate() {
            let receipt =
                CoseSign1::from_cbor(receipt_bytes.as_slice()).expect("valid receipt COSE_Sign1");
            let (int_keys, text_keys, has_x5chain) =
                inspect_mixed_key_header_map(receipt.protected_header);
            println!("receipt[{i}] protected int keys (subset): {int_keys:?}");
            println!("receipt[{i}] protected text keys (subset): {text_keys:?}");
            println!("receipt[{i}] has x5chain (label 33): {has_x5chain}");

            let out = verify_mst_receipt(ReceiptVerifyInput {
                statement_bytes_with_receipts: cose_bytes.as_slice(),
                receipt_bytes: receipt_bytes.as_slice(),
                offline_jwks_json: pack.offline_jwks_json.as_deref(),
                allow_network_fetch: pack.allow_network,
                jwks_api_version: pack.jwks_api_version.as_deref(),
            });

            match out {
                Ok(ok) => println!(
                    "receipt[{i}]: OK trusted={} details={:?}",
                    ok.trusted, ok.details
                ),
                Err(e) => println!("receipt[{i}]: ERR {e}"),
            }
        }
    }
}

fn inspect_mixed_key_header_map(map_bytes: &[u8]) -> (Vec<i64>, Vec<String>, bool) {
    let mut d = tinycbor::Decoder(map_bytes);
    let mut map = d.map_visitor().expect("protected header must be a map");

    let mut int_keys = Vec::new();
    let mut text_keys = Vec::new();
    let mut has_x5chain = false;

    while let Some(entry) = map.visit::<tinycbor::Any<'_>, tinycbor::Any<'_>>() {
        let (k_any, _v_any) = entry.expect("map entry decode failed");

        if let Some(k) = decode_cbor_i64_one(k_any.as_ref()) {
            if [1_i64, 3, 4, 15, 33, 395].contains(&k) {
                int_keys.push(k);
            }
            if k == 33 {
                has_x5chain = true;
            }
            continue;
        }

        if let Some(s) = decode_cbor_text_one(k_any.as_ref()) {
            // Print only a small subset to keep output readable.
            if ["ccf.v1", "type"].contains(&s.as_str()) {
                text_keys.push(s);
            }
        }
    }

    int_keys.sort();
    int_keys.dedup();
    text_keys.sort();
    text_keys.dedup();

    (int_keys, text_keys, has_x5chain)
}

fn decode_cbor_i64_one(bytes: &[u8]) -> Option<i64> {
    let (n, used) = decode_cbor_i64(bytes)?;
    if used == bytes.len() {
        Some(n)
    } else {
        None
    }
}

fn decode_cbor_i64(bytes: &[u8]) -> Option<(i64, usize)> {
    let first = *bytes.first()?;
    let major = first >> 5;
    let ai = first & 0x1f;

    let (unsigned, used) = decode_cbor_uint_value(ai, &bytes[1..])?;

    match major {
        0 => i64::try_from(unsigned).ok().map(|v| (v, 1 + used)),
        1 => {
            let n = i64::try_from(unsigned).ok()?;
            Some((-1 - n, 1 + used))
        }
        _ => None,
    }
}

fn decode_cbor_uint_value(ai: u8, rest: &[u8]) -> Option<(u64, usize)> {
    match ai {
        0..=23 => Some((ai as u64, 0)),
        24 => Some((u64::from(*rest.first()?), 1)),
        25 => {
            let b = rest.get(0..2)?;
            Some((u16::from_be_bytes([b[0], b[1]]) as u64, 2))
        }
        26 => {
            let b = rest.get(0..4)?;
            Some((u32::from_be_bytes([b[0], b[1], b[2], b[3]]) as u64, 4))
        }
        27 => {
            let b = rest.get(0..8)?;
            Some((
                u64::from_be_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]),
                8,
            ))
        }
        _ => None,
    }
}

fn decode_cbor_text_one(bytes: &[u8]) -> Option<String> {
    let first = *bytes.first()?;
    let major = first >> 5;
    let ai = first & 0x1f;
    if major != 3 {
        return None;
    }

    let (len, used) = decode_cbor_uint_value(ai, &bytes[1..])?;
    let len = usize::try_from(len).ok()?;
    let start = 1 + used;
    let end = start.checked_add(len)?;
    let s = std::str::from_utf8(bytes.get(start..end)?).ok()?;
    if end != bytes.len() {
        return None;
    }
    Some(s.to_string())
}
