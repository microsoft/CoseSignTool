package cose_trust_policy

# §6.5.10 #8 byte-equality pivot. The canonical IR produced by translating
# this Rego document MUST be byte-identical to the IR produced by translating
# its sibling cross/canonical_policy/canonical_policy.coseTrustPolicy.json,
# locking cross-frontend equivalence as a property of construction.
policy := {
    "combinator": "and",
    "message": {
        "fact": "content-type/v1",
        "predicate": {"matches": "application/cose"}
    },
    "primary_signing_key": {
        "all_of": [
            {"fact": "x509-chain-trusted/v1",         "predicate": {"is_trusted": true}},
            {"fact": "x509-cert-identity-allowed/v1", "predicate": {"is_allowed": true}}
        ]
    },
    "any_counter_signature": {
        "on_empty": "deny",
        "fact": "mst-receipt-trusted/v1",
        "predicate": {"is_trusted": true}
    }
}
