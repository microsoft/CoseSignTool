// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.TrustFrontends.Json.Tests;

using System.Text.Json;
using CoseSign1.Validation.Trust.Frontends;
using CoseSign1.Validation.TrustFrontends.Json;
using Microsoft.Extensions.DependencyInjection;

[TestFixture]
[Category("DI")]
public sealed class ServiceCollectionExtensionsTests
{
    [Test]
    public void AddCoseTpJsonFrontend_NullServices_Throws()
    {
        Assert.Throws<System.ArgumentNullException>(() =>
            TrustFrontendsJsonServiceCollectionExtensions.AddCoseTpJsonFrontend(null!));
    }

    [Test]
    public void AddCoseTpJsonFrontend_RegistersFrontendAsSingleton()
    {
        var services = new ServiceCollection();
        services.AddCoseTpJsonFrontend();
        using var sp = services.BuildServiceProvider();

        var front1 = sp.GetRequiredService<ICoseTrustPolicyFrontend<JsonDocument>>();
        var front2 = sp.GetRequiredService<ICoseTrustPolicyFrontend<JsonDocument>>();
        Assert.That(front2, Is.SameAs(front1));
        Assert.That(front1, Is.InstanceOf<CoseTpJsonFrontend>());
    }

    [Test]
    public void AddCoseTpJsonFrontend_RegistersTranslatorCacheAsSingleton()
    {
        var services = new ServiceCollection();
        services.AddCoseTpJsonFrontend(new TrustPolicyTranslatorOptions { CacheCapacity = 7 });
        using var sp = services.BuildServiceProvider();

        var cache1 = sp.GetRequiredService<TrustPolicyTranslatorCache>();
        var cache2 = sp.GetRequiredService<TrustPolicyTranslatorCache>();
        Assert.That(cache2, Is.SameAs(cache1));
        Assert.That(cache1.Capacity, Is.EqualTo(7));
    }
}
