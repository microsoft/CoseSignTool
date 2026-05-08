# Trust-policy examples

Shared fixtures that exercise the V2 trust-policy surface across both implementations.

| File | Format | Purpose |
|------|--------|---------|
| `canonical-policy.coseTrustPolicy.json` | `cose-tp-json/v1` | The canonical reference policy. Translates to the canonical IR the conformance suite uses for cross-port byte-equality testing. |
| `canonical-policy.coseTrustPolicy.rego` | `cose-tp-rego/v1` | Logical equivalent of the JSON file. Both translate to byte-identical canonical IR — verified by the cross-frontend conformance suite. |
| `verify-cross-port-equivalence.ps1` | PowerShell | Reproducible demo: runs the same policy file through both the .NET V2 CLI and the native Rust CLI; asserts exit-code and TPX diagnostic-code-set parity. |

## Cross-port portability contract

The same `.coseTrustPolicy.json` (or `.coseTrustPolicy.rego`) file is portable between the two implementations because of four protection layers — each enforced by a separate test in CI:

| Layer | What's locked | Test |
|-------|---------------|------|
| 1. **Schema byte-identical** | The embedded JSON Schema in the .NET frontend (`V2/schemas/cose-tp/v1.json`) and the embedded copy in the Rust frontend (`native/rust/validation/trustfrontends/json/schemas/cose-tp/v1.json`) are byte-identical after CRLF→LF normalisation. | `cose_sign1_trustfrontends_json::tests::cross_port_schema` (Rust) — fails the build if drift creeps in. |
| 2. **Canonical IR byte-equal** | Translating the same document with the .NET frontend and the Rust frontend produces byte-identical canonical-JSON IR. | `cose_sign1_trustfrontends_conformance::tests::cross_port_canonical_ir` (Rust) — golden-file assertion against the .NET-produced IR. |
| 3. **Fact id set identical** | The 16 stable v1 fact ids (`x509-chain-trusted/v1`, `mst-receipt-trusted/v1`, etc.) are tagged on both .NET and Rust fact CLR types via the same string literals. Renaming any v1 id is a v2 breaking change in either implementation. | `tests/conformance_baseline.rs` (Rust) asserts hand-rolled equals static baseline; .NET ships an attribute-driven equivalence test in `CoseSign1.Validation.Trust.PlanPolicy.Spec.Tests`. |
| 4. **CLI flag identical** | Both CLIs accept `--trust-policy <path-or-url>` + `--trust-policy-param key=value` (repeatable) with D8 override semantics (pack defaults bypassed when supplied). | `CoseSign1.Trust.Integration.Tests` (.NET, V2 Phase 6) + the equivalent Rust integration test (Phase 2 dispatch); plus the demo script in this directory. |

## What the contract does NOT cover

The portable surface is the **policy document** and the **canonical IR it translates to**. The runtime decision is NOT byte-equivalent across implementations in all cases. Specifically:

- **Pack fact producers** are independently implemented in .NET (`CoseSign1.Certificates`, `CoseSign1.Transparent.MST`) and Rust (`extension_packs/certificates`, `extension_packs/mst`). Edge cases in X.509 chain validation (e.g. revocation check semantics, basic-constraints enforcement, OCSP timeouts) may differ.
- **Diagnostic message text** is not part of the contract. Diagnostic *codes* (`TPX001`, `TPX200`, etc.) are. Operators integrating with logging / alerting systems should pattern-match on TPX codes, not message text.
- **Performance characteristics** differ. The Rust frontend uses `moka` LRU + `blake3` hashing (R4/R5); the .NET frontend uses an in-process LRU + SHA-256. Cache-hit behaviour is implementation-internal.

## Running the demo

```powershell
# Run the canonical policy through both CLIs:
cd V2/docs/examples/trust-policy
./verify-cross-port-equivalence.ps1 `
    -Signature path/to/signed.cose `
    -PayloadParams '{"trusted_log_hosts": ["dataplane.codetransparency.azure.net"]}'
```

If both CLIs are built and the policy is well-formed, you should see:

```
  ✅ EQUIVALENT — same exit code, same TPX diagnostic set.
```

A mismatch indicates a real cross-port regression — the protection layers above failed and one of the two implementations diverged. File an issue with both invocations' output and the failing fixture.

## Authoring portable policies

Stay inside the documented grammar surface and your policy is portable by construction:

- ✅ Stable fact ids (`x509-chain-trusted/v1`, `mst-receipt-trusted/v1`, …) — see `IFactRegistry.AllFactIds` for the complete list.
- ✅ Both predicate forms (property-shorthand + path/operator) — both compile to byte-identical IR.
- ✅ JSONC comments, trailing commas, `$param` references with optional `default`.
- ✅ Rego: the closed accept-list grammar (object/array/scalar literals, `input.<name>` refs, single `policy` rule).

Avoid:

- ❌ Pack-specific fact ids that haven't gone through the v1 contract review (the Rust train surfaced 17 such facts as Phase 1 baseline gaps; `.NET` has no equivalent fact ids today, so referencing them in a portable policy will produce TPX200 on the .NET side).
- ❌ Rego constructs outside the accept-list (`http.send`, `regex.match`, `some x in coll`, comprehensions, multiple rules per package). Both implementations reject these with TPX300/TPX301 family diagnostics, but the document was never portable.
