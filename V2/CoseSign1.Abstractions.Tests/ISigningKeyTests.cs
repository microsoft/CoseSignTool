// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

namespace CoseSign1.Abstractions.Tests;

using System.Security.Cryptography.Cose;

/// <summary>
/// Tests for ISigningKey and ISigningServiceKey interface contracts.
/// </summary>
[TestFixture]
public class ISigningKeyTests
{
    [Test]
    public void ISigningKey_ShouldDefineMinimalContract()
    {
        // Arrange & Act
        var type = typeof(ISigningKey);

        // Assert
        Assert.That(type.IsInterface, Is.True, "ISigningKey should be an interface");
        
        // ISigningKey should only have GetCoseKey - no Metadata or SigningService
        Assert.That(type.GetProperty("Metadata"), Is.Null, "ISigningKey should NOT have Metadata property (use ISigningServiceKey)");
        Assert.That(type.GetProperty("SigningService"), Is.Null, "ISigningKey should NOT have SigningService property (use ISigningServiceKey)");
    }

    [Test]
    public void ISigningKey_ShouldDefineGetCoseKeyMethod()
    {
        // Arrange & Act
        var getCoseKeyMethod = typeof(ISigningKey).GetMethod(nameof(ISigningKey.GetCoseKey));

        // Assert
        Assert.That(getCoseKeyMethod, Is.Not.Null, "Should have GetCoseKey method");
        Assert.That(getCoseKeyMethod!.ReturnType, Is.EqualTo(typeof(CoseKey)), "GetCoseKey should return CoseKey");

        var parameters = getCoseKeyMethod.GetParameters();
        Assert.That(parameters.Length, Is.EqualTo(0), "GetCoseKey should have no parameters");
    }

    [Test]
    public void ISigningKey_ShouldImplementIDisposable()
    {
        // Arrange & Act
        var type = typeof(ISigningKey);

        // Assert
        Assert.That(typeof(IDisposable).IsAssignableFrom(type), Is.True, "ISigningKey should implement IDisposable");

        // Verify Dispose is in the interface map
        var interfaces = type.GetInterfaces();
        Assert.That(interfaces, Does.Contain(typeof(IDisposable)), "ISigningKey should explicitly inherit IDisposable");
    }

    [Test]
    public void ISigningServiceKey_ShouldExtendISigningKey()
    {
        // Arrange & Act
        var type = typeof(ISigningServiceKey);

        // Assert
        Assert.That(type.IsInterface, Is.True, "ISigningServiceKey should be an interface");
        Assert.That(typeof(ISigningKey).IsAssignableFrom(type), Is.True, "ISigningServiceKey should extend ISigningKey");
    }

    [Test]
    public void ISigningServiceKey_ShouldDefineMetadataProperty()
    {
        // Arrange & Act
        var metadataProperty = typeof(ISigningServiceKey).GetProperty(nameof(ISigningServiceKey.Metadata));

        // Assert
        Assert.That(metadataProperty, Is.Not.Null, "ISigningServiceKey should have Metadata property");
        Assert.That(metadataProperty!.CanRead, Is.True, "Metadata should be readable");
        Assert.That(metadataProperty.PropertyType, Is.EqualTo(typeof(SigningKeyMetadata)), "Metadata should be SigningKeyMetadata type");
    }

    [Test]
    public void ISigningServiceKey_ShouldDefineSigningServiceProperty()
    {
        // Arrange & Act
        var signingServiceProperty = typeof(ISigningServiceKey).GetProperty(nameof(ISigningServiceKey.SigningService));

        // Assert
        Assert.That(signingServiceProperty, Is.Not.Null, "ISigningServiceKey should have SigningService property");
        Assert.That(signingServiceProperty!.CanRead, Is.True, "SigningService should be readable");
        Assert.That(signingServiceProperty.PropertyType, Is.EqualTo(typeof(ISigningService<SigningOptions>)), "SigningService should be ISigningService<SigningOptions> type");
    }

    [Test]
    public void ISigningServiceKey_ShouldInheritGetCoseKeyFromISigningKey()
    {
        // Arrange & Act
        var type = typeof(ISigningServiceKey);
        
        // ISigningServiceKey inherits from ISigningKey
        var inheritsFromISigningKey = typeof(ISigningKey).IsAssignableFrom(type);

        // The GetCoseKey method is available on the interface map of the base interface
        var baseInterfaceMap = type.GetInterfaces();
        var hasISigningKeyInHierarchy = baseInterfaceMap.Contains(typeof(ISigningKey));

        // Assert
        Assert.That(inheritsFromISigningKey, Is.True, "ISigningServiceKey should inherit from ISigningKey");
        Assert.That(hasISigningKeyInHierarchy, Is.True, "ISigningServiceKey should have ISigningKey in its interface hierarchy");
        
        // Verify the method exists on the base interface
        var getCoseKeyMethod = typeof(ISigningKey).GetMethod(nameof(ISigningKey.GetCoseKey));
        Assert.That(getCoseKeyMethod, Is.Not.Null, "ISigningKey should have GetCoseKey method");
        Assert.That(getCoseKeyMethod!.ReturnType, Is.EqualTo(typeof(CoseKey)), "GetCoseKey should return CoseKey");
    }
}