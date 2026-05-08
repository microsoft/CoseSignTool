package cose_trust_policy

policy := {
    "any_counter_signature": {
        "on_empty": "deny",
        "fact": "unknown-counter-signature-bytes/v1",
        "predicate": {"scope": "counter_signature"}
    }
}
