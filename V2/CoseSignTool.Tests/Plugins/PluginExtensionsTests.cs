// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.CommandLine;
using System.CommandLine.Parsing;
using System.Security.Cryptography.Cose;
using CoseSign1.Validation;
using CoseSignTool.Abstractions;

namespace CoseSignTool.Tests.Plugins;

/// <summary>
/// Tests for the PluginExtensions class.
/// </summary>
[TestFixture]
public class PluginExtensionsTests
{
    #region Default Constructor Tests

    [Test]
    public void DefaultConstructor_CreatesEmptySigningCommandProviders()
    {
        // Act
        var extensions = new PluginExtensions();

        // Assert
        Assert.That(extensions.SigningCommandProviders, Is.Empty);
    }

    [Test]
    public void DefaultConstructor_CreatesEmptyVerificationProviders()
    {
        // Act
        var extensions = new PluginExtensions();

        // Assert
        Assert.That(extensions.VerificationProviders, Is.Empty);
    }

    [Test]
    public void DefaultConstructor_CreatesEmptyTransparencyProviders()
    {
        // Act
        var extensions = new PluginExtensions();

        // Assert
        Assert.That(extensions.TransparencyProviders, Is.Empty);
    }

    #endregion

    #region Parameterized Constructor Tests

    [Test]
    public void Constructor_WithSigningProviders_SetsSigningCommandProviders()
    {
        // Arrange
        var signingProviders = new[] { new TestSigningCommandProvider() };

        // Act
        var extensions = new PluginExtensions(signingProviders, [], []);

        // Assert
        Assert.That(extensions.SigningCommandProviders.Count(), Is.EqualTo(1));
        Assert.That(extensions.SigningCommandProviders.First(), Is.InstanceOf<TestSigningCommandProvider>());
    }

    [Test]
    public void Constructor_WithVerificationProviders_SetsVerificationProviders()
    {
        // Arrange
        var verificationProviders = new[] { new TestVerificationProvider() };

        // Act
        var extensions = new PluginExtensions([], verificationProviders, []);

        // Assert
        Assert.That(extensions.VerificationProviders.Count(), Is.EqualTo(1));
        Assert.That(extensions.VerificationProviders.First(), Is.InstanceOf<TestVerificationProvider>());
    }

    [Test]
    public void Constructor_WithTransparencyProviders_SetsTransparencyProviders()
    {
        // Arrange
        var transparencyProviders = new[] { new TestTransparencyProviderContributor() };

        // Act
        var extensions = new PluginExtensions([], [], transparencyProviders);

        // Assert
        Assert.That(extensions.TransparencyProviders.Count(), Is.EqualTo(1));
        Assert.That(extensions.TransparencyProviders.First(), Is.InstanceOf<TestTransparencyProviderContributor>());
    }

    [Test]
    public void Constructor_WithNullSigningProviders_DefaultsToEmptyCollection()
    {
        // Act
        var extensions = new PluginExtensions(null!, [], []);

        // Assert
        Assert.That(extensions.SigningCommandProviders, Is.Empty);
    }

    [Test]
    public void Constructor_WithNullVerificationProviders_DefaultsToEmptyCollection()
    {
        // Act
        var extensions = new PluginExtensions([], null!, []);

        // Assert
        Assert.That(extensions.VerificationProviders, Is.Empty);
    }

    [Test]
    public void Constructor_WithNullTransparencyProviders_DefaultsToEmptyCollection()
    {
        // Act
        var extensions = new PluginExtensions([], [], null!);

        // Assert
        Assert.That(extensions.TransparencyProviders, Is.Empty);
    }

    [Test]
    public void Constructor_WithAllProviders_SetsAllProviders()
    {
        // Arrange
        var signingProviders = new[] { new TestSigningCommandProvider() };
        var verificationProviders = new[] { new TestVerificationProvider() };
        var transparencyProviders = new[] { new TestTransparencyProviderContributor() };

        // Act
        var extensions = new PluginExtensions(signingProviders, verificationProviders, transparencyProviders);

        // Assert
        Assert.That(extensions.SigningCommandProviders.Count(), Is.EqualTo(1));
        Assert.That(extensions.VerificationProviders.Count(), Is.EqualTo(1));
        Assert.That(extensions.TransparencyProviders.Count(), Is.EqualTo(1));
    }

    #endregion

    #region Static None Property Tests

    [Test]
    public void None_ReturnsEmptySigningCommandProviders()
    {
        // Act
        var extensions = PluginExtensions.None;

        // Assert
        Assert.That(extensions.SigningCommandProviders, Is.Empty);
    }

    [Test]
    public void None_ReturnsEmptyVerificationProviders()
    {
        // Act
        var extensions = PluginExtensions.None;

        // Assert
        Assert.That(extensions.VerificationProviders, Is.Empty);
    }

    [Test]
    public void None_ReturnsEmptyTransparencyProviders()
    {
        // Act
        var extensions = PluginExtensions.None;

        // Assert
        Assert.That(extensions.TransparencyProviders, Is.Empty);
    }

    [Test]
    public void None_ReturnsNewInstanceEachTime()
    {
        // Act
        var extensions1 = PluginExtensions.None;
        var extensions2 = PluginExtensions.None;

        // Assert - Each call to None creates a new instance
        Assert.That(extensions1, Is.Not.SameAs(extensions2));
    }

    #endregion

    #region Test Helper Classes

    private sealed class TestSigningCommandProvider : ISigningCommandProvider
    {
        public string CommandName => "test-sign";
        public string CommandDescription => "Test signing command";
        public string ExampleUsage => "--test-option value";
        public void AddCommandOptions(Command command) { }
        public Task<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>> CreateSigningServiceAsync(IDictionary<string, object?> options)
            => Task.FromResult<CoseSign1.Abstractions.ISigningService<CoseSign1.Abstractions.SigningOptions>>(null!);
        public IDictionary<string, string> GetSigningMetadata() => new Dictionary<string, string>();
    }

    private sealed class TestVerificationProvider : IVerificationProvider
    {
        public string ProviderName => "Test";
        public string Description => "Test verification provider";
        public int Priority => 50;
        public void AddVerificationOptions(Command command) { }
        public bool IsActivated(ParseResult parseResult) => true;
        public IEnumerable<IValidator<CoseSign1Message>> CreateValidators(ParseResult parseResult) => [];
        public IDictionary<string, object?> GetVerificationMetadata(ParseResult parseResult, CoseSign1Message message, ValidationResult validationResult) => new Dictionary<string, object?>();
    }

    private sealed class TestTransparencyProviderContributor : ITransparencyProviderContributor
    {
        public string ProviderName => "Test";
        public string ProviderDescription => "Test transparency provider";
        public Task<CoseSign1.Abstractions.Transparency.ITransparencyProvider> CreateTransparencyProviderAsync(IDictionary<string, object?> options, CancellationToken cancellationToken = default)
            => Task.FromResult<CoseSign1.Abstractions.Transparency.ITransparencyProvider>(null!);
    }

    #endregion
}
