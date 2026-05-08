// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Validation.Trust.PlanPolicy.Spec.Tests;

using System;
using CoseSign1.Validation.Trust.PlanPolicy.Spec.Registry;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Tests covering the Phase 3 DI extension that registers the attribute-driven fact registry.
/// </summary>
[TestFixture]
[Category("TrustPolicySpec")]
public sealed class AttributeDrivenFactRegistryServiceCollectionExtensionsTests
{
    [Test]
    public void AddAttributeDrivenFactRegistry_NullServices_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => AttributeDrivenFactRegistryServiceCollectionExtensions.AddAttributeDrivenFactRegistry(null!));
    }

    [Test]
    public void AddAttributeDrivenFactRegistry_RegistersIFactRegistry_AsSingleton()
    {
        var services = new ServiceCollection();
        services.AddAttributeDrivenFactRegistry();
        using var sp = services.BuildServiceProvider();

        var first = sp.GetRequiredService<IFactRegistry>();
        var second = sp.GetRequiredService<IFactRegistry>();

        Assert.That(first, Is.InstanceOf<AttributeDrivenFactRegistry>());
        Assert.That(second, Is.SameAs(first), "Singleton lifetime expected.");
    }

    [Test]
    public void AddAttributeDrivenFactRegistry_DiscoversShippedFacts()
    {
        var services = new ServiceCollection();
        services.AddAttributeDrivenFactRegistry();
        using var sp = services.BuildServiceProvider();

        var registry = sp.GetRequiredService<IFactRegistry>();
        Assert.That(registry.AllFactIds, Has.Count.EqualTo(16));
        Assert.That(registry.TryGetFactType("x509-chain-trusted/v1", out _), Is.True);
    }

    [Test]
    public void AddAttributeDrivenFactRegistry_IsIdempotent()
    {
        var services = new ServiceCollection();
        services.AddAttributeDrivenFactRegistry();
        services.AddAttributeDrivenFactRegistry();
        using var sp = services.BuildServiceProvider();

        var resolved = sp.GetServices<IFactRegistry>();
        Assert.That(resolved, Has.Exactly(1).InstanceOf<IFactRegistry>());
    }

    [Test]
    public void AddAttributeDrivenFactRegistry_DoesNotOverrideExistingRegistration()
    {
        var preExisting = new AttributeDrivenFactRegistry(Array.Empty<System.Reflection.Assembly>());
        var services = new ServiceCollection();
        services.AddSingleton<IFactRegistry>(preExisting);
        services.AddAttributeDrivenFactRegistry();
        using var sp = services.BuildServiceProvider();

        var resolved = sp.GetRequiredService<IFactRegistry>();
        Assert.That(resolved, Is.SameAs(preExisting));
        Assert.That(resolved.AllFactIds, Is.Empty);
    }

    [Test]
    public void AddAttributeDrivenFactRegistry_ReturnsSameServiceCollection()
    {
        var services = new ServiceCollection();
        var ret = services.AddAttributeDrivenFactRegistry();
        Assert.That(ret, Is.SameAs(services));
    }

    [Test]
    public void AddAttributeDrivenFactRegistry_WithUnrelatedRegistrations_StillRegisters()
    {
        // Existing registrations that are NOT IFactRegistry must be skipped over by the dedupe
        // loop without short-circuiting. Exercises both branches of the for-loop predicate.
        var services = new ServiceCollection();
        services.AddSingleton<string>("not-a-fact-registry");
        services.AddSingleton<object>(new object());
        services.AddAttributeDrivenFactRegistry();
        using var sp = services.BuildServiceProvider();

        Assert.That(sp.GetRequiredService<IFactRegistry>(), Is.InstanceOf<AttributeDrivenFactRegistry>());
        Assert.That(sp.GetRequiredService<string>(), Is.EqualTo("not-a-fact-registry"));
    }
}
