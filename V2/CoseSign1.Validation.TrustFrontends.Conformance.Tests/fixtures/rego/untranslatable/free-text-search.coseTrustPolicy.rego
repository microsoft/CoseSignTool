package cose_trust_policy

# Free-text-search-style construct — REJECTED because the constrained subset forbids the
# regex.* namespace.
policy := {
    "primary_signing_key": {
        "fact": "x509-cert-identity/v1",
        "predicate": {
            "operator": "Equals",
            "path": "$.subject",
            "value": regex.match("secret search phrase", "$.subject")
        }
    }
}
