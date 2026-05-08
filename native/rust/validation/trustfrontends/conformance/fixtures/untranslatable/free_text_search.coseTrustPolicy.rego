package cose_trust_policy

# Lowers to a JSON object that violates the cose-tp-json/v1 schema —
# 'free_text_search' is not a recognised expression key. Property #3 expects
# a TPX100 (schema-validation failure) on this fixture.
policy := {
    "primary_signing_key": {
        "free_text_search": "trust everything that mentions 'good'"
    }
}
