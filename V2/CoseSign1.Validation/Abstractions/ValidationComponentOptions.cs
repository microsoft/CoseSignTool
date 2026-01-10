// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Abstractions;

using CoseSign1.Validation.Interfaces;

/// <summary>
/// Specifies the caching strategy for validation component applicability checks.
/// </summary>
public enum CachingStrategy
{
    /// <summary>
    /// No caching. Each call to <see cref="IValidationComponent.IsApplicableTo"/> will compute applicability fresh.
    /// Use this for testing or when message applicability changes dynamically.
    /// </summary>
    None,

    /// <summary>
    /// Sliding window expiration. Cache entries expire after a period of inactivity.
    /// This is the default strategy, balancing memory usage with performance.
    /// </summary>
    SlidingExpiration,

    /// <summary>
    /// Absolute expiration. Cache entries expire after a fixed time regardless of access.
    /// Use this when applicability may change over time and you want guaranteed freshness.
    /// </summary>
    AbsoluteExpiration
}

/// <summary>
/// Configuration options for <see cref="ValidationComponentBase"/> behavior.
/// </summary>
/// <remarks>
/// <para>
/// This options class allows consumers to configure base class behavior without
/// modifying the component implementation. Derived classes can augment these options
/// with their own configuration as needed.
/// </para>
/// <para>
/// Default configuration uses sliding expiration with a 5-minute window, which is
/// appropriate for most validation scenarios.
/// </para>
/// </remarks>
public record ValidationComponentOptions
{
    /// <summary>
    /// Default cache expiration time (5 minutes).
    /// </summary>
    public static readonly TimeSpan DefaultCacheExpiration = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Gets the default options instance with sliding expiration and 5-minute cache window.
    /// </summary>
    public static ValidationComponentOptions Default { get; } = new();

    /// <summary>
    /// Gets options that disable caching entirely.
    /// </summary>
    public static ValidationComponentOptions NoCache { get; } = new() { CachingStrategy = CachingStrategy.None };

    /// <summary>
    /// Gets or sets the caching strategy for applicability checks.
    /// </summary>
    /// <value>The caching strategy. Defaults to <see cref="CachingStrategy.SlidingExpiration"/>.</value>
    public CachingStrategy CachingStrategy { get; init; } = CachingStrategy.SlidingExpiration;

    /// <summary>
    /// Gets or sets the cache expiration duration.
    /// </summary>
    /// <value>
    /// The duration for cache entries. Interpretation depends on <see cref="CachingStrategy"/>:
    /// <list type="bullet">
    /// <item><description><see cref="CachingStrategy.None"/>: This value is ignored.</description></item>
    /// <item><description><see cref="CachingStrategy.SlidingExpiration"/>: Time of inactivity before expiration.</description></item>
    /// <item><description><see cref="CachingStrategy.AbsoluteExpiration"/>: Fixed time until expiration.</description></item>
    /// </list>
    /// Defaults to 5 minutes.
    /// </value>
    public TimeSpan CacheExpiration { get; init; } = DefaultCacheExpiration;

    /// <summary>
    /// Creates options with sliding expiration and the specified duration.
    /// </summary>
    /// <param name="duration">The sliding expiration duration.</param>
    /// <returns>A new options instance configured for sliding expiration.</returns>
    public static ValidationComponentOptions WithSlidingExpiration(TimeSpan duration) =>
        new()
        {
            CachingStrategy = CachingStrategy.SlidingExpiration,
            CacheExpiration = duration
        };

    /// <summary>
    /// Creates options with absolute expiration and the specified duration.
    /// </summary>
    /// <param name="duration">The absolute expiration duration.</param>
    /// <returns>A new options instance configured for absolute expiration.</returns>
    public static ValidationComponentOptions WithAbsoluteExpiration(TimeSpan duration) =>
        new()
        {
            CachingStrategy = CachingStrategy.AbsoluteExpiration,
            CacheExpiration = duration
        };
}
