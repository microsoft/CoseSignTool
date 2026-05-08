package cose_trust_policy

import future.keywords.in

# Unconstrained iteration via 'some x in coll' — REJECTED.
some host in input.trusted_log_hosts

policy := {
    "any_counter_signature": {
        "on_empty": "deny",
        "fact": "mst-receipt-issuer-host/v1",
        "predicate": {
            "operator": "Equals",
            "path": "$.host",
            "value": host
        }
    }
}
