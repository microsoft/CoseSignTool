package cose_trust_policy

import future.keywords.in

# Logical equivalent of canonical-policy.coseTrustPolicy.json. Both files MUST
# translate to byte-identical canonical IR. This equivalence is a property of
# construction (the Rust + .NET Rego frontends both lower onto cose-tp-json/v1
# before walking) and is locked by the cross-frontend conformance test suite
# in CoseSign1.Validation.TrustFrontends.Conformance.

policy := {
    "primary_signing_key": {
        "all_of": [
            {"fact": "x509-chain-trusted/v1",         "predicate": {"is_trusted": true}},
            {"fact": "x509-cert-identity-allowed/v1", "predicate": {"is_allowed": true}}
        ]
    },
    "any_counter_signature": {
        "on_empty": "deny",
        "all_of": [
            {"fact": "mst-receipt-present/v1", "predicate": {"is_present": true}},
            {"fact": "mst-receipt-trusted/v1", "predicate": {"is_trusted": true}},
            {"fact": "mst-receipt-issuer-host/v1",
             "predicate": {
                 "operator": "In",
                 "path": "$.host",
                 "value": input.trusted_log_hosts
             }}
        ]
    },
    "combinator": "and"
}
