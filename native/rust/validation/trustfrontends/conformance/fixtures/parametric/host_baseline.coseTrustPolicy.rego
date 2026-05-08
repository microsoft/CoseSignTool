package cose_trust_policy

policy := {
    "primary_signing_key": {
        "all_of": [
            {
                "fact": "x509-cert-identity/v1",
                "predicate": {"thumbprint": input.expected_thumbprint}
            },
            {
                "fact": "x509-cert-identity-allowed/v1",
                "predicate": {"is_allowed": input.must_be_allowed}
            }
        ]
    }
}
