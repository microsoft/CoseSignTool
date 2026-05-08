package cose_trust_policy

policy := {
    "primary_signing_key": {
        "fact": "x509-cert-basic-constraints/v1",
        "predicate": {"certificate_authority": true}
    }
}
