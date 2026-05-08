// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Conformance.Tests;

using System.Text.Json;

/// <summary>
/// JSON-frontend conformance test fixture. Inherits the eight §6.5.10 properties from
/// <see cref="FrontendConformanceTestBase{TDocument}"/>; NUnit auto-discovers the inherited
/// [Test] methods.
/// </summary>
[TestFixture]
public sealed class JsonFrontendConformanceTests : FrontendConformanceTestBase<JsonDocument>
{
    /// <inheritdoc />
    protected override IConformanceFrontendAdapter<JsonDocument> CreateAdapter() => new JsonConformanceAdapter();
}
