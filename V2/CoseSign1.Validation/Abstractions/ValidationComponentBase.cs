// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Abstractions;

using System.Diagnostics.CodeAnalysis;
using System.Runtime.Caching;
using System.Runtime.CompilerServices;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation.Interfaces;

/// <summary>
/// Abstract base class for all validation components providing common applicability checking
/// with configurable caching optimization.
/// </summary>
/// <remarks>
/// <para>
/// This base class provides:
/// <list type="bullet">
/// <item><description>Default <see cref="IsApplicableTo"/> implementation returning <c>true</c> for non-null messages</description></item>
/// <item><description>Configurable caching of applicability results (sliding, absolute, or none)</description></item>
/// <item><description>Protected <see cref="ComputeApplicability"/> method for derived classes to override</description></item>
/// </list>
/// </para>
/// <para>
/// The caching mechanism uses <see cref="MemoryCache"/> with configurable expiration to prevent
/// memory growth in long-running processes. Caching behavior is controlled via
/// <see cref="ValidationComponentOptions"/> passed to the constructor.
/// </para>
/// <para>
/// Derived classes should override <see cref="ComputeApplicability"/> to specify their
/// applicability criteria. Do not override <see cref="IsApplicableTo"/> except for unit testing.
/// </para>
/// </remarks>
public abstract class ValidationComponentBase : IValidationComponent
{
    [ExcludeFromCodeCoverage]
    internal static class ClassStrings
    {
        public const string CacheName = "ValidationComponentApplicabilityCache";
        public const string CacheKeySeparator = ":";
    }

    // Use a shared cache with component-specific key prefixes
    private static readonly MemoryCache SharedCache = new(ClassStrings.CacheName);

    /// <summary>
    /// Gets the component options controlling caching behavior.
    /// </summary>
    protected ValidationComponentOptions ComponentOptions { get; }

    /// <summary>
    /// Initializes a new instance of the <see cref="ValidationComponentBase"/> class with default options.
    /// </summary>
    protected ValidationComponentBase()
        : this(null)
    {
    }

    /// <summary>
    /// Initializes a new instance of the <see cref="ValidationComponentBase"/> class with the specified options.
    /// </summary>
    /// <param name="options">The component options, or null to use defaults.</param>
    protected ValidationComponentBase(ValidationComponentOptions? options)
    {
        ComponentOptions = options ?? ValidationComponentOptions.Default;
    }

    /// <inheritdoc/>
    public abstract string ComponentName { get; }

    /// <inheritdoc/>
    /// <remarks>
    /// <para>
    /// This method handles caching internally and calls <see cref="ComputeApplicability"/>
    /// for the actual determination. Override <see cref="ComputeApplicability"/> to specify
    /// applicability criteria - do not override this method except for unit testing purposes.
    /// </para>
    /// <para>
    /// This method is virtual only to allow mocking in unit tests.
    /// </para>
    /// </remarks>
    public virtual bool IsApplicableTo(CoseSign1Message? message, CoseSign1ValidationOptions? options = null)
    {
        if (message == null)
        {
            return false;
        }

        // Skip caching if disabled
        if (ComponentOptions.CachingStrategy == CachingStrategy.None)
        {
            return ComputeApplicability(message, options);
        }

        // Create a unique cache key combining component type, message identity, and relevant options
        // Note: We include options hash to ensure different option configurations get separate cache entries
        int optionsHash = options?.CertificateHeaderLocation.GetHashCode() ?? 0;
        string cacheKey = GetType().FullName + ClassStrings.CacheKeySeparator + RuntimeHelpers.GetHashCode(message) + ClassStrings.CacheKeySeparator + optionsHash;

        if (SharedCache.Get(cacheKey) is bool cachedResult)
        {
            return cachedResult;
        }

        bool isApplicable = ComputeApplicability(message, options);

        var policy = new CacheItemPolicy();
        switch (ComponentOptions.CachingStrategy)
        {
            case CachingStrategy.SlidingExpiration:
                policy.SlidingExpiration = ComponentOptions.CacheExpiration;
                break;
            case CachingStrategy.AbsoluteExpiration:
                policy.AbsoluteExpiration = DateTimeOffset.UtcNow.Add(ComponentOptions.CacheExpiration);
                break;
        }

        SharedCache.Set(cacheKey, isApplicable, policy);
        return isApplicable;
    }

    /// <summary>
    /// Computes whether this component is applicable to the given message.
    /// </summary>
    /// <param name="message">The non-null message to check.</param>
    /// <param name="options">Optional validation options that may affect applicability.</param>
    /// <returns><c>true</c> if this component should process this message; otherwise, <c>false</c>.</returns>
    /// <remarks>
    /// <para>
    /// Override this method to specify when your component is applicable.
    /// The base implementation returns <c>true</c> for all messages.
    /// </para>
    /// <para>
    /// This method is called by <see cref="IsApplicableTo"/> only when the result is not
    /// already cached. You do not need to implement caching - it is handled automatically.
    /// </para>
    /// </remarks>
    protected virtual bool ComputeApplicability(CoseSign1Message message, CoseSign1ValidationOptions? options = null) => true;

    /// <summary>
    /// Clears the applicability cache for this component.
    /// </summary>
    /// <remarks>
    /// Call this if the component's state changes in a way that affects applicability.
    /// Note: This clears entries for this component type only.
    /// </remarks>
    protected void ClearApplicabilityCache()
    {
        string prefix = GetType().FullName + ClassStrings.CacheKeySeparator;
        var keysToRemove = SharedCache
            .Where(kvp => kvp.Key.StartsWith(prefix, StringComparison.Ordinal))
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var key in keysToRemove)
        {
            SharedCache.Remove(key);
        }
    }
}
