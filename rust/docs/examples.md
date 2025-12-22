<!--
Copyright (c) Microsoft Corporation.
Licensed under the MIT License.
-->

# Examples

This page contains copy/paste-friendly snippets to consume the Rust port.

## Verify from bytes (in-memory)

```rust
use cosesign1::CoseSign1;

fn verify(cose: &[u8], pubkey: &[u8]) -> bool {
    let msg = CoseSign1::from_bytes(cose).expect("parse");
    msg.verify_signature(None, Some(pubkey)).is_valid
}
```

## Minimal CLI pattern

```rust
use cosesign1::CoseSign1;

fn main() {
    let cose = std::fs::read("message.cose").unwrap();
    let pubkey = std::fs::read("public_key.der").unwrap();

    let msg = CoseSign1::from_bytes(&cose).unwrap();
    let res = msg.verify_signature(None, Some(&pubkey));

    if res.is_valid {
        println!("OK");
    } else {
        eprintln!("FAIL: {res:?}");
        std::process::exit(1);
    }
}
```

For a working version, see `rust/docs/hello-world/`.
