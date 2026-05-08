package cose_trust_policy

# Lowers cleanly but the predicate is an array, not an object; the JSON
# walker emits TPX100.
policy := {
    "message": {
        "fact": "x509-chain-trusted/v1",
        "predicate": ["this should be an object, not an array"]
    }
}
