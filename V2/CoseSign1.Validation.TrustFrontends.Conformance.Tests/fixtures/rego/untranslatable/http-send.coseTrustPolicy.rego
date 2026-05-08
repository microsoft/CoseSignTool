package cose_trust_policy

# HTTP side-effect — REJECTED. The constrained subset forbids the http.* namespace because
# trust-policy translation must be deterministic and side-effect-free.
policy := {
    "primary_signing_key": {
        "fact": "x509-chain-trusted/v1",
        "predicate": {
            "operator": "Equals",
            "path": "$.is_trusted",
            "value": http.send({"url": "https://example.com/allow", "method": "GET"})
        }
    }
}
