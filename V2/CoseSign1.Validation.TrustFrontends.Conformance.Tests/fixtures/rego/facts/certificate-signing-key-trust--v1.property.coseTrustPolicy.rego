package cose_trust_policy

policy := {
    "primary_signing_key": {
        "fact": "certificate-signing-key-trust/v1",
        "predicate": {"chain_trusted": true}
    }
}
