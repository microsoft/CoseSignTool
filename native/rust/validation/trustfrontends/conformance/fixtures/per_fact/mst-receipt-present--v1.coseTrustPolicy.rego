package cose_trust_policy

policy := {
    "any_counter_signature": {
        "on_empty": "deny",
        "fact": "mst-receipt-present/v1",
        "predicate": {"is_present": true}
    }
}
