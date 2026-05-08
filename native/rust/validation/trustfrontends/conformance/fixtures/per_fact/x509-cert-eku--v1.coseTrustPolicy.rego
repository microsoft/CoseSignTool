package cose_trust_policy

policy := {
    "primary_signing_key": {
        "fact": "x509-cert-eku/v1",
        "predicate": {"has_codesigning": true}
    }
}
