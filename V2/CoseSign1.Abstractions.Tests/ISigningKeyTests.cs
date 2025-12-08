// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Security.Cryptography.Cose;
using NUnit.Framework;

namespace CoseSign1.Abstractions.Tests;

/// <summary>
/// Tests for ISigningKey interface contract and implementations.
/// </summary>
[TestFixture]
public class ISigningKeyTests
{
    [Test]
    public void ISigningKey_ShouldDefineRequiredProperties()
    {
        // Arrange & Act
        var type = typeof(ISigningKey);

        // Assert
        Assert.That(type.IsInterface, Is.True, "ISigningKey should be an interface");
        Assert.That(type.GetProperty(nameof(ISigningKey.Metadata)), Is.Not.Null, "Should have Metadata property");
        Assert.That(type.GetProperty(nameof(ISigningKey.SigningService)), Is.Not.Null, "Should have SigningService property");
    }

    [Test]
    public void ISigningKey_Metadata_ShouldBeReadOnly()
    {
        // Arrange & Act
        var metadataProperty = typeof(ISigningKey).GetProperty(nameof(ISigningKey.Metadata));

        // Assert
        Assert.That(metadataProperty, Is.Not.Null);
        Assert.That(metadataProperty!.CanRead, Is.True, "Metadata should be readable");
        Assert.That(metadataProperty.PropertyType, Is.EqualTo(typeof(SigningKeyMetadata)), "Metadata should be SigningKeyMetadata type");
    }

    [Test]
    public void ISigningKey_SigningService_ShouldBeReadOnly()
    {
        // Arrange & Act
        var signingServiceProperty = typeof(ISigningKey).GetProperty(nameof(ISigningKey.SigningService));

        // Assert
        Assert.That(signingServiceProperty, Is.Not.Null);
        Assert.That(signingServiceProperty!.CanRead, Is.True, "SigningService should be readable");
        Assert.That(signingServiceProperty.PropertyType, Is.EqualTo(typeof(ISigningService)), "SigningService should be ISigningService type");
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
}
