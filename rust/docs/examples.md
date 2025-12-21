<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Examples

This page contains copy/paste-friendly snippets to consume the Rust port.

## Verify from bytes (in-memory)

```rust
use cosesign1_validation::{verify_cose_sign1, VerifyOptions};

fn verify(cose: &[u8], pubkey: &[u8]) -> bool {
    let opts = VerifyOptions {
        public_key_bytes: Some(pubkey.to_vec()),
        ..Default::default()
    };
    verify_cose_sign1("Verifier", cose, &opts).is_valid
}
```

## Minimal CLI pattern

```rust
use cosesign1_validation::{verify_cose_sign1, VerifyOptions};

fn main() {
    let cose = std::fs::read("message.cose").unwrap();
    let pubkey = std::fs::read("public_key.der").unwrap();

    let opts = VerifyOptions { public_key_bytes: Some(pubkey), ..Default::default() };
    let res = verify_cose_sign1("Verifier", &cose, &opts);

    if res.is_valid {
        println!("OK");
    } else {
        eprintln!("FAIL: {res:?}");
        std::process::exit(1);
    }
}
```

For a working version, see `rust/docs/hello-world/`.
