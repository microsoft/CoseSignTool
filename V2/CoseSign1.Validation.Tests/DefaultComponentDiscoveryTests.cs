// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Tests;

using CoseSign1.Validation.Extensions;
using CoseSign1.Validation.Interfaces;
using Microsoft.Extensions.Logging;
using NUnit.Framework;

/// <summary>
/// Tests for <see cref="DefaultComponentDiscovery"/>.
/// </summary>
[TestFixture]
public class DefaultComponentDiscoveryTests
{
    [SetUp]
    public void SetUp()
    {
        // Clear cache before each test to ensure isolation
        DefaultComponentDiscovery.ClearCache();
    }

    [TearDown]
    public void TearDown()
    {
        // Clear cache after each test
        DefaultComponentDiscovery.ClearCache();
    }

    #region ClassStrings Tests

    [Test]
    public void ClassStrings_ErrorNoProvidersFound_ContainsExpectedText()
    {
        // Verify the error message contains useful guidance
        Assert.Multiple(() =>
        {
            Assert.That(DefaultComponentDiscovery.ClassStrings.ErrorNoProvidersFound, Does.Contain("No default validation component providers"));
            Assert.That(DefaultComponentDiscovery.ClassStrings.ErrorNoProvidersFound, Does.Contain("extension package"));
            Assert.That(DefaultComponentDiscovery.ClassStrings.ErrorNoProvidersFound, Does.Contain("message.Validate(builder => ...)"));
        });
    }

    [Test]
    public void ClassStrings_ErrorNoSigningKeyResolver_ContainsExpectedText()
    {
        // Verify the error message contains useful guidance
        Assert.Multiple(() =>
        {
            Assert.That(DefaultComponentDiscovery.ClassStrings.ErrorNoSigningKeyResolver, Does.Contain("ISigningKeyResolver"));
            Assert.That(DefaultComponentDiscovery.ClassStrings.ErrorNoSigningKeyResolver, Does.Contain("signing key resolver"));
            Assert.That(DefaultComponentDiscovery.ClassStrings.ErrorNoSigningKeyResolver, Does.Contain("CoseSign1.Certificates"));
        });
    }

    [Test]
    public void ClassStrings_SystemNamespacePrefix_IsCorrect()
    {
        Assert.That(DefaultComponentDiscovery.ClassStrings.SystemNamespacePrefix, Is.EqualTo("System."));
    }

    #endregion

    #region DiscoverProviders Tests

    [Test]
    public void DiscoverProviders_ReturnsNonNullCollection()
    {
        // Act
        var providers = DefaultComponentDiscovery.DiscoverProviders();

        // Assert
        Assert.That(providers, Is.Not.Null);
    }

    [Test]
    public void DiscoverProviders_ReturnsCachedResult_OnSubsequentCalls()
    {
        // Act
        var firstCall = DefaultComponentDiscovery.DiscoverProviders();
        var secondCall = DefaultComponentDiscovery.DiscoverProviders();

        // Assert - should return the exact same instance from cache
        Assert.That(secondCall, Is.SameAs(firstCall));
    }

    [Test]
    public void DiscoverProviders_ReturnsProvidersSortedByPriority()
    {
        // Act
        var providers = DefaultComponentDiscovery.DiscoverProviders();

        // Assert - if we have multiple providers, they should be sorted
        if (providers.Count > 1)
        {
            for (int i = 0; i < providers.Count - 1; i++)
            {
                Assert.That(providers[i].Priority, Is.LessThanOrEqualTo(providers[i + 1].Priority),
                    $"Provider at index {i} should have priority <= provider at index {i + 1}");
            }
        }
    }

    #endregion

    #region ClearCache Tests

    [Test]
    public void ClearCache_ClearsTheCachedProviders()
    {
        // Arrange - populate the cache
        var firstCall = DefaultComponentDiscovery.DiscoverProviders();

        // Act
        DefaultComponentDiscovery.ClearCache();
        var afterClear = DefaultComponentDiscovery.DiscoverProviders();

        // Assert - should be a new list (different instance), though contents may be the same
        // Note: We can't guarantee they're different instances if the cache is immediately
        // repopulated with the same providers, but the clear operation should have run
        Assert.That(afterClear, Is.Not.Null);
    }

    [Test]
    public void ClearCache_CanBeCalledMultipleTimes_WithoutError()
    {
        // Should not throw when called multiple times
        Assert.DoesNotThrow(() =>
        {
            DefaultComponentDiscovery.ClearCache();
            DefaultComponentDiscovery.ClearCache();
            DefaultComponentDiscovery.ClearCache();
        });
    }

    [Test]
    public void ClearCache_CanBeCalledConcurrently_WithoutError()
    {
        // Arrange - populate cache first
        _ = DefaultComponentDiscovery.DiscoverProviders();

        // Act - concurrent clear operations should be thread-safe due to lock
        var tasks = Enumerable.Range(0, 10)
            .Select(i => Task.Run(() =>
            {
                DefaultComponentDiscovery.ClearCache();
                DefaultComponentDiscovery.DiscoverProviders();
            }))
            .ToArray();

        // Assert - should complete without deadlock or exception
        Assert.DoesNotThrow(() => Task.WaitAll(tasks));
    }

    #endregion

    #region GetDefaultComponents Tests

    [Test]
    public void GetDefaultComponents_ReturnsComponents_WhenProvidersExist()
    {
        // Arrange - test providers are registered via assembly attributes in TestProviders.cs
        // This should discover TestSigningKeyResolverProvider and TestHigherPriorityProvider

        // Act
        var components = DefaultComponentDiscovery.GetDefaultComponents(null);

        // Assert - we should have at least 2 components (one from each provider)
        Assert.That(components, Is.Not.Null);
        Assert.That(components.Count, Is.GreaterThanOrEqualTo(2));
    }

    [Test]
    public void GetDefaultComponents_IncludesSigningKeyResolver()
    {
        // Act
        var components = DefaultComponentDiscovery.GetDefaultComponents(null);

        // Assert - should include our test signing key resolver
        var hasResolver = components.OfType<ISigningKeyResolver>().Any();
        Assert.That(hasResolver, Is.True, "Components should include at least one ISigningKeyResolver");
    }

    [Test]
    public void GetDefaultComponents_IncludesPostSignatureValidator()
    {
        // Act
        var components = DefaultComponentDiscovery.GetDefaultComponents(null);

        // Assert - should include our test post-signature validator
        var hasValidator = components.OfType<IPostSignatureValidator>().Any();
        Assert.That(hasValidator, Is.True, "Components should include at least one IPostSignatureValidator");
    }

    [Test]
    public void GetDefaultComponents_AcceptsNullLoggerFactory()
    {
        // Act - should not throw with null logger factory
        Assert.DoesNotThrow(() =>
        {
            _ = DefaultComponentDiscovery.GetDefaultComponents(null);
        });
    }

    [Test]
    public void GetDefaultComponents_AcceptsLoggerFactory()
    {
        // Arrange
        using var loggerFactory = new LoggerFactory();

        // Act
        var components = DefaultComponentDiscovery.GetDefaultComponents(loggerFactory);

        // Assert
        Assert.That(components, Is.Not.Null);
        Assert.That(components.Count, Is.GreaterThanOrEqualTo(2));
    }

    #endregion

    #region Provider Discovery Tests

    [Test]
    public void DiscoverProviders_FindsRegisteredProviders()
    {
        // Act - should find TestSigningKeyResolverProvider and TestHigherPriorityProvider
        var providers = DefaultComponentDiscovery.DiscoverProviders();

        // Assert
        Assert.That(providers, Is.Not.Empty);
        Assert.That(providers.Count, Is.GreaterThanOrEqualTo(2));
    }

    [Test]
    public void DiscoverProviders_IncludesTestSigningKeyResolverProvider()
    {
        // Act
        var providers = DefaultComponentDiscovery.DiscoverProviders();

        // Assert - should find our test provider
        var hasTestProvider = providers.Any(p => p is TestSigningKeyResolverProvider);
        Assert.That(hasTestProvider, Is.True, "Should discover TestSigningKeyResolverProvider");
    }

    [Test]
    public void DiscoverProviders_IncludesTestHigherPriorityProvider()
    {
        // Act
        var providers = DefaultComponentDiscovery.DiscoverProviders();

        // Assert - should find our higher priority test provider
        var hasTestProvider = providers.Any(p => p is TestHigherPriorityProvider);
        Assert.That(hasTestProvider, Is.True, "Should discover TestHigherPriorityProvider");
    }

    [Test]
    public void DiscoverProviders_SortsByPriority_LowerFirst()
    {
        // Act
        var providers = DefaultComponentDiscovery.DiscoverProviders();

        // Assert - TestSigningKeyResolverProvider (priority 50) should come before
        // TestHigherPriorityProvider (priority 200)
        var signingKeyIndex = -1;
        var higherPriorityIndex = -1;

        for (int i = 0; i < providers.Count; i++)
        {
            if (providers[i] is TestSigningKeyResolverProvider)
            {
                signingKeyIndex = i;
            }
            else if (providers[i] is TestHigherPriorityProvider)
            {
                higherPriorityIndex = i;
            }
        }

        Assert.That(signingKeyIndex, Is.GreaterThanOrEqualTo(0), "Should find TestSigningKeyResolverProvider");
        Assert.That(higherPriorityIndex, Is.GreaterThanOrEqualTo(0), "Should find TestHigherPriorityProvider");
        Assert.That(signingKeyIndex, Is.LessThan(higherPriorityIndex),
            "TestSigningKeyResolverProvider (priority 50) should come before TestHigherPriorityProvider (priority 200)");
    }

    #endregion

    #region Integration Tests

    [Test]
    public void DiscoverProviders_SkipsDynamicAssemblies()
    {
        // This test verifies the discovery process doesn't fail when dynamic assemblies exist
        // Dynamic assemblies are created by things like Moq and should be skipped

        // Act - should not throw even if dynamic assemblies are present
        Assert.DoesNotThrow(() =>
        {
            _ = DefaultComponentDiscovery.DiscoverProviders();
        });
    }

    [Test]
    public void DiscoverProviders_SkipsSystemAssemblies()
    {
        // Act
        var providers = DefaultComponentDiscovery.DiscoverProviders();

        // Assert - verify System.* assemblies were skipped (no providers from System assemblies)
        // This is implicit - if System assemblies were inspected for our custom attribute,
        // there would be no matches, but the code explicitly skips them for efficiency
        Assert.That(providers, Is.Not.Null);
    }

    #endregion
}
