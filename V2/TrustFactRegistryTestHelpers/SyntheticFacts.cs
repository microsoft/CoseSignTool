// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace TrustFactRegistryTestHelpers;

using CoseSign1.Validation.Trust.Facts;

/// <summary>Synthetic fact used to verify that the registry surfaces a tagged type by id.</summary>
[TrustFactId(ClassStrings.FactIdSyntheticAlpha)]
public sealed class SyntheticAlphaFact
{
}

/// <summary>Synthetic fact used to verify the registry's lookup-by-type path.</summary>
[TrustFactId(ClassStrings.FactIdSyntheticBeta)]
public sealed class SyntheticBetaFact
{
}

/// <summary>
/// Deliberately collides with <see cref="SyntheticAlphaFact"/> on the same id so the
/// duplicate-id (TPX300) code path is testable without polluting any other test's view.
/// </summary>
[TrustFactId(ClassStrings.FactIdSyntheticAlpha)]
public sealed class SyntheticAlphaCollidingFact
{
}

/// <summary>Reference type with no <c>[TrustFactId]</c>; the registry must ignore it.</summary>
public sealed class UntaggedFact
{
}
