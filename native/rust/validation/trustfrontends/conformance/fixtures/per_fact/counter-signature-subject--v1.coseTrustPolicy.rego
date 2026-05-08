package cose_trust_policy

policy := {
    "any_counter_signature": {
        "on_empty": "allow",
        "fact": "counter-signature-subject/v1",
        "predicate": {"matches": true}
    }
}
