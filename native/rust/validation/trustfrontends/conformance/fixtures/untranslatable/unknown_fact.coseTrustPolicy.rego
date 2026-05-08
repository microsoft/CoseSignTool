package cose_trust_policy

# Lowers cleanly but the fact id is not in the host's capability surface;
# the JSON walker emits TPX200 (capability-aware translation, §6.5.10 #5).
policy := {
    "primary_signing_key": {
        "fact": "made-up-fact/v1",
        "predicate": {"is_trusted": true}
    }
}
