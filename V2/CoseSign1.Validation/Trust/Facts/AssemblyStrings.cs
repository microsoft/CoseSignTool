// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.Facts;

using System.Diagnostics.CodeAnalysis;

/// <summary>
/// String-literal pool for the trust-fact infrastructure (currently only used by
/// <see cref="TrustFactIdAttribute"/>). Centralised so the repo's <c>StringLiteralAnalyzer</c>
/// can spot any user-visible literal at a glance.
/// </summary>
[ExcludeFromCodeCoverage]
internal static class AssemblyStrings
{
    internal const string TrustFactIdPattern = "^[a-z][a-z0-9-]*\\/v[0-9]+$";
    internal const string ErrTrustFactIdMalformedFormat = "Trust fact id '{0}' is malformed; expected '<lowercase-kebab>/v<digits>' (regex {1}).";

    // Stable fact ids for facts shipped from CoseSign1.Validation. Co-located with the
    // [TrustFactId] attribute so the ids referenced by the in-assembly facts and the ids
    // baked into the (legacy) StaticFactRegistry baseline come from the same source-of-truth.
    internal const string FactIdContentType = "content-type/v1";
    internal const string FactIdCounterSignatureSubject = "counter-signature-subject/v1";
    internal const string FactIdDetachedPayloadPresent = "detached-payload-present/v1";
    internal const string FactIdUnknownCounterSignatureBytes = "unknown-counter-signature-bytes/v1";
}
