// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Extensions;

using System.Reflection;
using CoseSign1.Validation.Abstractions;
using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;

/// <summary>
/// Discovers and loads default validation components from loaded assemblies.
/// </summary>
/// <remarks>
/// <para>
/// This service scans loaded assemblies for types marked with
/// <see cref="DefaultValidationComponentProviderAttribute"/> and instantiates them
/// to provide default validation components.
/// </para>
/// <para>
/// Extension packages can participate in auto-discovery by:
/// <list type="number">
/// <item><description>Implementing <see cref="IDefaultValidationComponentProvider"/></description></item>
/// <item><description>Adding <c>[assembly: DefaultValidationComponentProvider(typeof(YourProvider))]</c></description></item>
/// </list>
/// </para>
/// </remarks>
internal static class DefaultComponentDiscovery
{
    internal static class ClassStrings
    {
        public const string ErrorNoProvidersFound = "No default validation component providers were discovered. " +
            "Ensure that at least one extension package with default components is referenced, " +
            "or configure validation explicitly using message.Validate(builder => ...).";

        public const string ErrorNoSigningKeyResolver = "Auto-discovered components do not include a signing key resolver (ISigningKeyResolver). " +
            "At least one extension package must provide a signing key resolver for validation to work. " +
            "Consider adding CoseSign1.Certificates or another signing key package.";

        public const string SystemNamespacePrefix = "System.";
    }

    private static List<IDefaultValidationComponentProvider>? CachedProviders;
    private static readonly object CacheLock = new();

    /// <summary>
    /// Discovers all default validation component providers from loaded assemblies.
    /// </summary>
    /// <returns>An ordered list of providers sorted by priority.</returns>
    public static IReadOnlyList<IDefaultValidationComponentProvider> DiscoverProviders()
    {
        lock (CacheLock)
        {
            if (CachedProviders != null)
            {
                return CachedProviders;
            }

            var providers = new List<IDefaultValidationComponentProvider>();

            foreach (var assembly in AppDomain.CurrentDomain.GetAssemblies())
            {
                // Skip dynamic assemblies and system assemblies
                if (assembly.IsDynamic || assembly.FullName?.StartsWith(ClassStrings.SystemNamespacePrefix, StringComparison.Ordinal) == true)
                {
                    continue;
                }

                try
                {
                    var attributes = assembly.GetCustomAttributes<DefaultValidationComponentProviderAttribute>();
                    foreach (var attr in attributes)
                    {
                        if (Activator.CreateInstance(attr.ProviderType) is IDefaultValidationComponentProvider provider)
                        {
                            providers.Add(provider);
                        }
                    }
                }
                catch
                {
                    // Ignore assemblies that can't be inspected
                }
            }

            // Sort by priority (lower first)
            providers.Sort((a, b) => a.Priority.CompareTo(b.Priority));
            CachedProviders = providers;
            return providers;
        }
    }

    /// <summary>
    /// Gets all default validation components from discovered providers.
    /// </summary>
    /// <param name="loggerFactory">Optional logger factory for creating loggers.</param>
    /// <returns>All default validation components.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when no providers are found or when no signing key resolver is provided.
    /// </exception>
    public static IReadOnlyList<IValidationComponent> GetDefaultComponents(ILoggerFactory? loggerFactory)
    {
        var providers = DiscoverProviders();

        if (providers.Count == 0)
        {
            throw new InvalidOperationException(ClassStrings.ErrorNoProvidersFound);
        }

        var components = new List<IValidationComponent>();
        foreach (var provider in providers)
        {
            components.AddRange(provider.GetDefaultComponents(loggerFactory));
        }

        // Validate that we have at least one signing key resolver
        if (!components.OfType<ISigningKeyResolver>().Any())
        {
            throw new InvalidOperationException(ClassStrings.ErrorNoSigningKeyResolver);
        }

        return components;
    }

    /// <summary>
    /// Clears the cached providers. Used for testing.
    /// </summary>
    internal static void ClearCache()
    {
        lock (CacheLock)
        {
            CachedProviders = null;
        }
    }
}
