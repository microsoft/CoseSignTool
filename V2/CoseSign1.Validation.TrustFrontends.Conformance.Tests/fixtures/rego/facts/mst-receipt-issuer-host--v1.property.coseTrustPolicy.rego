package cose_trust_policy

policy := {
    "any_counter_signature": {
        "on_empty": "deny",
        "fact": "mst-receipt-issuer-host/v1",
        "predicate": {"scope": "counter_signature"}
    }
}
