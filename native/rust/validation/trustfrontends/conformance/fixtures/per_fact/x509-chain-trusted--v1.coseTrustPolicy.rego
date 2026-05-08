package cose_trust_policy

policy := {
    "primary_signing_key": {
        "fact": "x509-chain-trusted/v1",
        "predicate": {"is_trusted": true}
    }
}
