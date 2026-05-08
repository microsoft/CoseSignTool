package cose_trust_policy

# 70 levels of nesting — exceeds the cose-tp-rego/v1 hard cap of 64. Surfaces TPX305.
policy := {
    "primary_signing_key": {
        "fact": "x509-chain-trusted/v1",
        "predicate": {"value": [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[ 1 ]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]}
    }
}