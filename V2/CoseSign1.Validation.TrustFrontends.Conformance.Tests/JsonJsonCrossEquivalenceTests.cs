// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Conformance.Tests;

using System.Text.Json;

/// <summary>
/// Cross-frontend equivalence harness pinned to the JSON frontend. The (json, json) pair is
/// degenerate — same adapter on both sides — but locks the harness in CI so when Phase 5a
/// Rego ships the (json, rego) pair lights up automatically. The new fixture
/// <c>JsonRegoCrossEquivalenceTests : CrossFrontendEquivalenceTestBase&lt;JsonDocument, RegoDocument&gt;</c>
/// will compose the two adapters with no change to the harness itself.
/// </summary>
[TestFixture]
public sealed class JsonJsonCrossEquivalenceTests : CrossFrontendEquivalenceTestBase<JsonDocument, JsonDocument>
{
    /// <inheritdoc />
    protected override IConformanceFrontendAdapter<JsonDocument> CreateAdapterA() => new JsonConformanceAdapter();

    /// <inheritdoc />
    protected override IConformanceFrontendAdapter<JsonDocument> CreateAdapterB() => new JsonConformanceAdapter();
}
