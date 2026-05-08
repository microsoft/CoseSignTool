// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json;

/// <summary>
/// Configuration knobs for the in-process translator cache (<see cref="TrustPolicyTranslatorCache"/>).
/// </summary>
public sealed record TrustPolicyTranslatorOptions
{
    /// <summary>
    /// Gets the maximum number of cached translation results retained in the in-process LRU
    /// cache. Default value is 32 per design decision D9.
    /// </summary>
    public int CacheCapacity { get; init; } = 32;
}
