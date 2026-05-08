package cose_trust_policy

policy := {
    "primary_signing_key": {
        "fact": "x509-cert-key-usage/v1",
        "predicate": {"certificate_thumbprint": "ABCDEF1234567890"}
    }
}
