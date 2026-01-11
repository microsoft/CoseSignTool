// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.AzureKeyVault.Tests.Validation;

using CoseSign1.AzureKeyVault.Validation;
using CoseSign1.Validation.Interfaces;
using Moq;
using NUnit.Framework;

/// <summary>
/// Tests for <see cref="AzureKeyVaultValidationExtensions"/>.
/// </summary>
[TestFixture]
[Category("AzureKeyVault")]
[Category("Validation")]
public class AzureKeyVaultValidationExtensionsTests
{
    #region ValidateAzureKeyVault Extension Method Tests

    [Test]
    public void ValidateAzureKeyVault_WithNullBuilder_ThrowsArgumentNullException()
    {
        ICoseSign1ValidationBuilder? builder = null;

        Assert.Throws<ArgumentNullException>(() =>
            builder!.ValidateAzureKeyVault(akv => akv.RequireAzureKeyVaultOrigin()));
    }

    [Test]
    public void ValidateAzureKeyVault_WithNullConfigure_ThrowsArgumentNullException()
    {
        var mockBuilder = new Mock<ICoseSign1ValidationBuilder>();

        Assert.Throws<ArgumentNullException>(() =>
            mockBuilder.Object.ValidateAzureKeyVault(null!));
    }

    [Test]
    public void ValidateAzureKeyVault_WithRequireAzureKeyVaultOrigin_AddsComponent()
    {
        var mockBuilder = new Mock<ICoseSign1ValidationBuilder>();
        mockBuilder.Setup(b => b.AddComponent(It.IsAny<AzureKeyVaultAssertionProvider>()))
            .Returns(mockBuilder.Object);

        var result = mockBuilder.Object.ValidateAzureKeyVault(akv => akv.RequireAzureKeyVaultOrigin());

        mockBuilder.Verify(b => b.AddComponent(It.Is<AzureKeyVaultAssertionProvider>(p => p != null)), Times.Once);
        Assert.That(result, Is.SameAs(mockBuilder.Object));
    }

    [Test]
    public void ValidateAzureKeyVault_WithFromAllowedVaults_AddsComponent()
    {
        var mockBuilder = new Mock<ICoseSign1ValidationBuilder>();
        mockBuilder.Setup(b => b.AddComponent(It.IsAny<AzureKeyVaultAssertionProvider>()))
            .Returns(mockBuilder.Object);

        var result = mockBuilder.Object.ValidateAzureKeyVault(akv =>
            akv.FromAllowedVaults("https://myvault.vault.azure.net/keys/*"));

        mockBuilder.Verify(b => b.AddComponent(It.Is<AzureKeyVaultAssertionProvider>(p => p != null)), Times.Once);
        Assert.That(result, Is.SameAs(mockBuilder.Object));
    }

    [Test]
    public void ValidateAzureKeyVault_WithMultipleAllowedVaults_AddsComponent()
    {
        var mockBuilder = new Mock<ICoseSign1ValidationBuilder>();
        mockBuilder.Setup(b => b.AddComponent(It.IsAny<AzureKeyVaultAssertionProvider>()))
            .Returns(mockBuilder.Object);

        var result = mockBuilder.Object.ValidateAzureKeyVault(akv =>
            akv.FromAllowedVaults(
                "https://vault1.vault.azure.net/keys/*",
                "https://vault2.vault.azure.net/keys/*"));

        mockBuilder.Verify(b => b.AddComponent(It.Is<AzureKeyVaultAssertionProvider>(p => p != null)), Times.Once);
        Assert.That(result, Is.SameAs(mockBuilder.Object));
    }

    [Test]
    public void ValidateAzureKeyVault_WithEmptyConfigure_DoesNotAddComponent()
    {
        var mockBuilder = new Mock<ICoseSign1ValidationBuilder>();
        mockBuilder.Setup(b => b.AddComponent(It.IsAny<AzureKeyVaultAssertionProvider>()))
            .Returns(mockBuilder.Object);

        var result = mockBuilder.Object.ValidateAzureKeyVault(akv => { });

        mockBuilder.Verify(b => b.AddComponent(It.IsAny<AzureKeyVaultAssertionProvider>()), Times.Never);
        Assert.That(result, Is.SameAs(mockBuilder.Object));
    }

    [Test]
    public void ValidateAzureKeyVault_FluentChaining_Works()
    {
        var mockBuilder = new Mock<ICoseSign1ValidationBuilder>();
        mockBuilder.Setup(b => b.AddComponent(It.IsAny<AzureKeyVaultAssertionProvider>()))
            .Returns(mockBuilder.Object);

        // Test fluent API - FromAllowedVaults then RequireAzureKeyVaultOrigin
        var result = mockBuilder.Object.ValidateAzureKeyVault(akv =>
            akv.FromAllowedVaults("https://myvault.vault.azure.net/keys/*")
               .RequireAzureKeyVaultOrigin());

        mockBuilder.Verify(b => b.AddComponent(It.Is<AzureKeyVaultAssertionProvider>(p => p != null)), Times.Once);
    }

    #endregion

    #region Builder Implementation Tests

    [Test]
    public void FromAllowedVaults_WithNullPatterns_CreatesProviderWithEmptyList()
    {
        var mockBuilder = new Mock<ICoseSign1ValidationBuilder>();
        IValidationComponent? capturedProvider = null;

        mockBuilder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>()))
            .Callback<IValidationComponent>(p => capturedProvider = p)
            .Returns(mockBuilder.Object);

        mockBuilder.Object.ValidateAzureKeyVault(akv => akv.FromAllowedVaults(null!));

        Assert.That(capturedProvider, Is.Not.Null);
        Assert.That(capturedProvider, Is.TypeOf<AzureKeyVaultAssertionProvider>());
    }

    [Test]
    public void FromAllowedVaults_WithEmptyPatterns_CreatesProviderWithEmptyList()
    {
        var mockBuilder = new Mock<ICoseSign1ValidationBuilder>();
        IValidationComponent? capturedProvider = null;

        mockBuilder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>()))
            .Callback<IValidationComponent>(p => capturedProvider = p)
            .Returns(mockBuilder.Object);

        mockBuilder.Object.ValidateAzureKeyVault(akv => akv.FromAllowedVaults());

        Assert.That(capturedProvider, Is.Not.Null);
        Assert.That(capturedProvider, Is.TypeOf<AzureKeyVaultAssertionProvider>());
    }

    [Test]
    public void FromAllowedVaults_WithRegexPattern_CreatesProvider()
    {
        var mockBuilder = new Mock<ICoseSign1ValidationBuilder>();
        IValidationComponent? capturedProvider = null;

        mockBuilder.Setup(b => b.AddComponent(It.IsAny<IValidationComponent>()))
            .Callback<IValidationComponent>(p => capturedProvider = p)
            .Returns(mockBuilder.Object);

        mockBuilder.Object.ValidateAzureKeyVault(akv =>
            akv.FromAllowedVaults("regex:https://.*\\.vault\\.azure\\.net/keys/.*"));

        Assert.That(capturedProvider, Is.Not.Null);
        Assert.That(capturedProvider, Is.TypeOf<AzureKeyVaultAssertionProvider>());
    }

    #endregion
}
