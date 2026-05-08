package cose_trust_policy

policy := {
    "primary_signing_key": {
        "fact": "x509-cert-identity/v1",
        "predicate": {"thumbprint": "abc123"}
    }
}
