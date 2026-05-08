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
internal static class ClassStrings
{
    internal const string TrustFactIdPattern = "^[a-z][a-z0-9-]*\\/v[0-9]+$";
    internal const string ErrTrustFactIdMalformedFormat = "Trust fact id '{0}' is malformed; expected '<lowercase-kebab>/v<digits>' (regex {1}).";
}
