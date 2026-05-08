package cose_trust_policy

# §6.5.10 #8 byte-equality pivot — must produce a TrustPolicySpec byte-identical to the
# JSON cross fixture under cose-tp-json/v1.
policy := {
    "primary_signing_key": {
        "fact": "x509-chain-trusted/v1",
        "predicate": {"is_trusted": true}
    },
    "any_counter_signature": {
        "on_empty": "deny",
        "fact": "mst-receipt-trusted/v1",
        "predicate": {"is_trusted": true}
    }
}
