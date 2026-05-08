// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Conformance.Tests;

using System.Collections.Generic;
using System.Text.Json;
using CoseSign1.Validation.TrustFrontends.Rego;

/// <summary>
/// Cross-frontend equivalence harness pinning the (json, rego) pair. The §6.5.10 #8
/// contract: same logical policy expressed in both frontends MUST produce byte-identical
/// canonical IRs. This fixture lights up automatically as soon as both adapters advertise
/// the supplied logical names — no machinery beyond the shared
/// <see cref="CrossFrontendEquivalenceTestBase{TDocumentA, TDocumentB}"/>.
/// </summary>
/// <remarks>
/// <para>
/// We extend the default fixture set (<c>cross/canonical-policy</c>) with the 16
/// per-fact property-form fixtures so the attribute-fidelity matrix lights up in Rego:
/// every registered fact has a Rego document expressing the same logical predicate as the
/// JSON property-form fixture, and the canonical IRs match byte-for-byte. The hybrid
/// path/operator-form check (§6.5.10 #2) remains a JSON-frontend-specific contract — Rego
/// has only one canonical form per fact (per the README accept-list).
/// </para>
/// </remarks>
[TestFixture]
public sealed class JsonRegoCrossEquivalenceTests : CrossFrontendEquivalenceTestBase<JsonDocument, RegoDocument>
{
    /// <inheritdoc />
    protected override IConformanceFrontendAdapter<JsonDocument> CreateAdapterA() => new JsonConformanceAdapter();

    /// <inheritdoc />
    protected override IConformanceFrontendAdapter<RegoDocument> CreateAdapterB() => new RegoConformanceAdapter();

    /// <inheritdoc />
    protected override IEnumerable<string> LogicalFixtureNames()
    {
        // 1. The canonical multi-scope cross fixture (the byte-equality pivot).
        yield return "cross/canonical-policy";

        // 2. Per-fact attribute-fidelity matrix (16 fact ids; property form only — the
        //    hybrid path/operator form is JSON-specific). The list mirrors the JSON
        //    fact-fixture set under fixtures/json/facts so any drift is surfaced as a
        //    cross-frontend IR mismatch in CI rather than a silent skip.
        yield return "facts/x509-chain-trusted--v1.property";
        yield return "facts/x509-chain-element-identity--v1.property";
        yield return "facts/x509-cert-eku--v1.property";
        yield return "facts/x509-cert-identity--v1.property";
        yield return "facts/x509-cert-identity-allowed--v1.property";
        yield return "facts/x509-cert-basic-constraints--v1.property";
        yield return "facts/x509-cert-key-usage--v1.property";
        yield return "facts/x509-x5chain-cert-identity--v1.property";
        yield return "facts/certificate-signing-key-trust--v1.property";
        yield return "facts/content-type--v1.property";
        yield return "facts/counter-signature-subject--v1.property";
        yield return "facts/detached-payload-present--v1.property";
        yield return "facts/mst-receipt-present--v1.property";
        yield return "facts/mst-receipt-trusted--v1.property";
        yield return "facts/mst-receipt-issuer-host--v1.property";
        yield return "facts/unknown-counter-signature-bytes--v1.property";
    }
}
