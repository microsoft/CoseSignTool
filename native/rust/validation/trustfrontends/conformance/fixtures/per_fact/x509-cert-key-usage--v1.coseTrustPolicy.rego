package cose_trust_policy

policy := {
    "primary_signing_key": {
        "fact": "x509-cert-key-usage/v1",
        "predicate": {"has_digital_signature": true}
    }
}
