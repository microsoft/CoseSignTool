package cose_trust_policy

policy := {
    "any_counter_signature": {
        "on_empty": "allow",
        "fact": "unknown-counter-signature-bytes/v1",
        "predicate": {"is_present": false}
    }
}
