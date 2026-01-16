// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Factories.Tests;

using CoseSign1.Abstractions;
using CoseSign1.Abstractions.Transparency;
using CoseSign1.Factories;
using CoseSign1.Factories.Direct;
using CoseSign1.Factories.Indirect;
using System.Security.Cryptography.Cose;
using Microsoft.Extensions.DependencyInjection;
using Moq;

[TestFixture]
public class CoseSign1FactoriesServiceCollectionExtensionsTests
{
    [Test]
    public void AddCoseSign1Factories_WhenServicesIsNull_ThrowsArgumentNullException()
    {
        IServiceCollection services = null!;
        _ = Assert.Throws<ArgumentNullException>(() => services.AddCoseSign1Factories());
    }

    [Test]
    public void AddCoseSign1Factories_RegistersAndResolvesFactoriesAndRouter()
    {
        var services = new ServiceCollection();
        services.AddSingleton(CreateMockSigningService().Object);

        _ = services.AddCoseSign1Factories();

        using var provider = services.BuildServiceProvider();

        var direct = provider.GetRequiredService<DirectSignatureFactory>();
        var indirect = provider.GetRequiredService<IndirectSignatureFactory>();
        var router = provider.GetRequiredService<ICoseSign1MessageFactoryRouter>();

        var directTyped = provider.GetRequiredService<ICoseSign1MessageFactory<DirectSignatureOptions>>();
        var indirectTyped = provider.GetRequiredService<ICoseSign1MessageFactory<IndirectSignatureOptions>>();

        Assert.That(direct, Is.TypeOf<DirectSignatureFactory>());
        Assert.That(indirect, Is.TypeOf<IndirectSignatureFactory>());
        Assert.That(directTyped, Is.TypeOf<DirectSignatureFactory>());
        Assert.That(indirectTyped, Is.TypeOf<IndirectSignatureFactory>());
        Assert.That(router, Is.TypeOf<CoseSign1MessageFactory>());
    }

    [Test]
    public void AddCoseSign1Factories_WhenReadOnlyListTransparencyProvidersRegistered_UsesThatList()
    {
        var services = new ServiceCollection();
        services.AddSingleton(CreateMockSigningService().Object);

        var list = new List<ITransparencyProvider> { new TestTransparencyProvider("P1") };
        services.AddSingleton<IReadOnlyList<ITransparencyProvider>>(list);

        _ = services.AddCoseSign1Factories();
        using var provider = services.BuildServiceProvider();

        var direct = provider.GetRequiredService<DirectSignatureFactory>();

        Assert.That(direct.TransparencyProviders, Is.SameAs(list));
        Assert.That(direct.TransparencyProviders!.Count, Is.EqualTo(1));
    }

    [Test]
    public void AddCoseSign1Factories_WhenEnumerableTransparencyProvidersRegistered_UsesEnumeratedProviders()
    {
        var services = new ServiceCollection();
        services.AddSingleton(CreateMockSigningService().Object);

        services.AddSingleton<ITransparencyProvider>(new TestTransparencyProvider("P1"));

        _ = services.AddCoseSign1Factories();
        using var provider = services.BuildServiceProvider();

        var direct = provider.GetRequiredService<DirectSignatureFactory>();

        Assert.That(direct.TransparencyProviders, Is.Not.Null);
        Assert.That(direct.TransparencyProviders!.Count, Is.EqualTo(1));
        Assert.That(direct.TransparencyProviders![0].ProviderName, Is.EqualTo("P1"));
    }

    [Test]
    public void AddCoseSign1Factories_WhenNoTransparencyProvidersRegistered_LeavesProvidersNull()
    {
        var services = new ServiceCollection();
        services.AddSingleton(CreateMockSigningService().Object);

        _ = services.AddCoseSign1Factories();
        using var provider = services.BuildServiceProvider();

        var direct = provider.GetRequiredService<DirectSignatureFactory>();

        Assert.That(direct.TransparencyProviders, Is.Null);
    }

    private static Mock<ISigningService<SigningOptions>> CreateMockSigningService()
        => new Mock<ISigningService<SigningOptions>>();

    private sealed class TestTransparencyProvider : ITransparencyProvider
    {
        public TestTransparencyProvider(string providerName)
        {
            ProviderName = providerName;
        }

        public string ProviderName { get; }

        public Task<CoseSign1Message> AddTransparencyProofAsync(
            CoseSign1Message message,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(message);
        }

        public Task<TransparencyValidationResult> VerifyTransparencyProofAsync(
            CoseSign1Message message,
            CancellationToken cancellationToken = default)
        {
            return Task.FromResult(TransparencyValidationResult.Success(ProviderName));
        }
    }
}
