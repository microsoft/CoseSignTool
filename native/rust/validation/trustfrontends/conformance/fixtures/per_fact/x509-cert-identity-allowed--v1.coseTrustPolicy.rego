package cose_trust_policy

policy := {
    "primary_signing_key": {
        "fact": "x509-cert-identity-allowed/v1",
        "predicate": {"is_allowed": true}
    }
}
