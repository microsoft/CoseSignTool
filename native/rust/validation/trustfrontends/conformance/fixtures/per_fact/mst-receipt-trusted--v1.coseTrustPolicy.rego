package cose_trust_policy

policy := {
    "any_counter_signature": {
        "on_empty": "deny",
        "fact": "mst-receipt-trusted/v1",
        "predicate": {"is_trusted": true}
    }
}
