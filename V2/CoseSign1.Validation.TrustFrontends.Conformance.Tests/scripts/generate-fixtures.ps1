# Generates conformance fixtures for the JSON frontend. Run from the V2 directory:
#   pwsh ./CoseSign1.Validation.TrustFrontends.Conformance.Tests/scripts/generate-fixtures.ps1
#
# This script is the source-of-truth for the fixture set. Fixtures themselves are committed
# alongside the test project so the build doesn't depend on Powershell at test-time, but the
# script lets a human regenerate them when a new fact is added or an existing fact's
# property surface changes.

$ErrorActionPreference = "Stop"
$root = Join-Path $PSScriptRoot "..\fixtures\json"
New-Item -ItemType Directory -Force -Path $root | Out-Null
foreach ($sub in @("facts", "untranslatable", "capability", "schema", "parametric", "perf", "cross")) {
    New-Item -ItemType Directory -Force -Path (Join-Path $root $sub) | Out-Null
}

# (id, scope_key, prop, value-as-json)
$facts = @(
    @("content-type/v1",                 "message",               "content_type",          '"application/cose"'),
    @("counter-signature-subject/v1",    "message",               "is_protected_header",   "true"),
    @("detached-payload-present/v1",     "message",               "present",               "true"),
    @("unknown-counter-signature-bytes/v1","any_counter_signature","scope",                '"counter_signature"'),
    @("certificate-signing-key-trust/v1","primary_signing_key",   "chain_trusted",         "true"),
    @("x509-chain-element-identity/v1",  "primary_signing_key",   "depth",                 "0"),
    @("x509-chain-trusted/v1",           "primary_signing_key",   "is_trusted",            "true"),
    @("x509-cert-basic-constraints/v1",  "primary_signing_key",   "certificate_authority", "true"),
    @("x509-cert-eku/v1",                "primary_signing_key",   "oid_value",             '"1.3.6.1.5.5.7.3.3"'),
    @("x509-cert-identity-allowed/v1",   "primary_signing_key",   "is_allowed",            "true"),
    @("x509-cert-identity/v1",           "primary_signing_key",   "subject",               '"CN=test"'),
    @("x509-cert-key-usage/v1",          "primary_signing_key",   "certificate_thumbprint",'"ABCDEF1234567890"'),
    @("x509-x5chain-cert-identity/v1",   "primary_signing_key",   "subject",               '"CN=test"'),
    @("mst-receipt-issuer-host/v1",      "any_counter_signature", "scope",                 '"counter_signature"'),
    @("mst-receipt-present/v1",          "any_counter_signature", "is_present",            "true"),
    @("mst-receipt-trusted/v1",          "any_counter_signature", "is_trusted",            "true")
)

function Write-Fixture($path, $content) {
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($content)
    [System.IO.File]::WriteAllBytes($path, $bytes)
}

function Wrap-Counter($scope, $body) {
    if ($scope -eq "any_counter_signature") {
        return "{`n    `"on_empty`": `"deny`",`n    `"fact`": $($body.fact_pred)`n  }"
    }
    return $body
}

foreach ($f in $facts) {
    $id = $f[0]; $scope = $f[1]; $prop = $f[2]; $val = $f[3]
    $fileSafe = $id -replace '/', '_'

    $propPred = "{ `"$prop`": $val }"
    $pathPred = "{ `"operator`": `"Equals`", `"path`": `"`$.$prop`", `"value`": $val }"

    foreach ($pair in @(@(".property", $propPred), @(".path-operator", $pathPred))) {
        $suffix = $pair[0]; $pred = $pair[1]
        $name = "$fileSafe$suffix"
        if ($scope -eq "any_counter_signature") {
            $doc = @"
{
  "frontend": "cose-tp-json/v1",
  "$scope": {
    "on_empty": "deny",
    "fact": "$id",
    "predicate": $pred
  }
}
"@
        } else {
            $doc = @"
{
  "frontend": "cose-tp-json/v1",
  "$scope": {
    "fact": "$id",
    "predicate": $pred
  }
}
"@
        }
        Write-Fixture (Join-Path $root "facts\$name.coseTrustPolicy.json") $doc
    }
}

# Untranslatable fixtures.
# Free-text search: operator outside the closed enum. Schema rejects with TPX100.
$freeTextDoc = @"
{
  "frontend": "cose-tp-json/v1",
  "primary_signing_key": {
    "fact": "x509-cert-identity/v1",
    "predicate": { "operator": "FullTextSearch", "path": "`$.subject", "value": "secret search phrase" }
  }
}
"@
Write-Fixture (Join-Path $root "untranslatable\free-text-search.coseTrustPolicy.json") $freeTextDoc

# Unknown-fact: structurally well-formed; surfaces TPX200 when AvailableFacts excludes it
# (the conformance suite always passes the live registry, so this fact id is by definition
# absent from the registry and thus from AvailableFacts).
$unknownFactDoc = @"
{
  "frontend": "cose-tp-json/v1",
  "primary_signing_key": {
    "fact": "totally-not-a-real-fact-id/v1",
    "predicate": { "operator": "Equals", "path": "`$.foo", "value": true }
  }
}
"@
Write-Fixture (Join-Path $root "untranslatable\unknown-fact.coseTrustPolicy.json") $unknownFactDoc

# Unknown-operator: another operator outside the closed enum. Schema rejects with TPX100.
# Distinct from free-text-search so the Conformance_3 matrix exercises two flavours of the
# same failure mode (the §6.5.10 #3 design doc lists "free-text", "aggregations", and
# "joins" as three classes of untranslatable shapes; the JSON frontend's response to all
# three is schema rejection because the predicate enum is closed).
$unknownOperatorDoc = @"
{
  "frontend": "cose-tp-json/v1",
  "primary_signing_key": {
    "fact": "x509-chain-trusted/v1",
    "predicate": { "operator": "RegexMatch", "path": "`$.is_trusted", "value": ".*" }
  }
}
"@
Write-Fixture (Join-Path $root "untranslatable\unknown-operator.coseTrustPolicy.json") $unknownOperatorDoc

# Capability missing-fact.
$capabilityDoc = @"
{
  "frontend": "cose-tp-json/v1",
  "primary_signing_key": {
    "fact": "x509-chain-trusted/v1",
    "predicate": { "is_trusted": true }
  }
}
"@
Write-Fixture (Join-Path $root "capability\missing-fact.coseTrustPolicy.json") $capabilityDoc

# Schema fixtures.
$malformedJson = @"
{
  "frontend": "cose-tp-json/v1",
  "primary_signing_key": {
    "fact": "x509-chain-trusted/v1",
    "predicate": { "is_trusted": true
"@
Write-Fixture (Join-Path $root "schema\malformed.coseTrustPolicy.malformed.txt") $malformedJson

$shapeViolation = @"
{
  "frontend": "cose-tp-json/v1"
}
"@
Write-Fixture (Join-Path $root "schema\shape-violation.coseTrustPolicy.json") $shapeViolation

# Parametric.
$parametricBaseline = @"
{
  "frontend": "cose-tp-json/v1",
  "any_counter_signature": {
    "on_empty": "deny",
    "fact": "mst-receipt-issuer-host/v1",
    "predicate": {
      "operator": "Contains",
      "path": "`$.hosts",
      "value": { "`$param": "trusted_host", "default": "issuer.example.com" }
    }
  }
}
"@
Write-Fixture (Join-Path $root "parametric\host-baseline.coseTrustPolicy.json") $parametricBaseline

$parametricAlternate = @"
{
  "frontend": "cose-tp-json/v1",
  "primary_signing_key": {
    "fact": "x509-cert-identity/v1",
    "predicate": {
      "operator": "Equals",
      "path": "`$.subject",
      "value": { "`$param": "trusted_host", "default": "alternate.example.com" }
    }
  }
}
"@
Write-Fixture (Join-Path $root "parametric\host-alternate.coseTrustPolicy.json") $parametricAlternate

# Perf representative <=1KB.
$perf = @"
{
  "frontend": "cose-tp-json/v1",
  "primary_signing_key": {
    "all_of": [
      { "fact": "x509-chain-trusted/v1", "predicate": { "is_trusted": true } },
      { "fact": "x509-cert-eku/v1", "predicate": { "operator": "Equals", "path": "`$.oid_value", "value": "1.3.6.1.5.5.7.3.3" } }
    ]
  },
  "any_counter_signature": {
    "on_empty": "deny",
    "fact": "mst-receipt-trusted/v1",
    "predicate": { "is_trusted": true }
  }
}
"@
Write-Fixture (Join-Path $root "perf\representative-1kb.coseTrustPolicy.json") $perf

# Cross-equivalence canonical pivot.
$cross = @"
{
  "frontend": "cose-tp-json/v1",
  "primary_signing_key": {
    "fact": "x509-chain-trusted/v1",
    "predicate": { "is_trusted": true }
  },
  "any_counter_signature": {
    "on_empty": "deny",
    "fact": "mst-receipt-trusted/v1",
    "predicate": { "is_trusted": true }
  }
}
"@
Write-Fixture (Join-Path $root "cross\canonical-policy.coseTrustPolicy.json") $cross

Write-Host "Fixtures regenerated under $root"
