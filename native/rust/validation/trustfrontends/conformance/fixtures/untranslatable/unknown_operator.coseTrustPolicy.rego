package cose_trust_policy

# Path/operator predicate with an operator the cose-tp-json/v1 schema does
# not enumerate; the JSON walker emits TPX100.
policy := {
    "primary_signing_key": {
        "fact": "x509-chain-trusted/v1",
        "predicate": {"path": "$.is_trusted", "operator": "FuzzyMatch", "value": true}
    }
}
