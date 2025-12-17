// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using System.Collections.Generic;
using CoseSign1.Certificates;
using CoseSign1.Certificates.AzureTrustedSigning.Extensions;
using CoseSign1.Headers;

namespace CoseSign1.Certificates.AzureTrustedSigning.Tests;

/// <summary>
/// Tests for <see cref="ScittExtensions"/>.
/// </summary>
[TestFixture]
public class ScittExtensionsTests
{
    private X509Certificate2 TestCert = null!;

    /// <summary>
    /// Microsoft Code Signing EKU: 1.3.6.1.4.1.311.10.3.13
    /// </summary>
    private const string MicrosoftCodeSigningEku = "1.3.6.1.4.1.311.10.3.13";

    [SetUp]
    public void Setup()
    {
        TestCert = TestCertificateUtils.CreateCertificate("ScittTest");
    }

    [TearDown]
    public void TearDown()
    {
        TestCert?.Dispose();
    }

    #region ConfigureForAzureScitt Basic Overload Tests

    [Test]
    public void ConfigureForAzureScitt_WithNullOptions_ThrowsArgumentNullException()
    {
        // Arrange
        var chain = new[] { TestCert };

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            ScittExtensions.ConfigureForAzureScitt(null!, chain));

        Assert.That(ex.ParamName, Is.EqualTo("options"));
    }

    [Test]
    public void ConfigureForAzureScitt_WithNullCertificateChain_ThrowsArgumentNullException()
    {
        // Arrange
        var options = new CertificateSigningOptions();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            options.ConfigureForAzureScitt(null!));

        Assert.That(ex.ParamName, Is.EqualTo("certificateChain"));
    }

    [Test]
    public void ConfigureForAzureScitt_WithEmptyChain_ThrowsArgumentException()
    {
        // Arrange
        var options = new CertificateSigningOptions();
        var emptyChain = Array.Empty<X509Certificate2>();

        // Act & Assert - AzureTrustedSigningDidX509.Generate throws ArgumentException for empty chain
        Assert.Throws<ArgumentException>(() =>
            options.ConfigureForAzureScitt(emptyChain));
    }

    [Test]
    public void ConfigureForAzureScitt_WithCertWithoutMicrosoftEku_ThrowsInvalidOperationException()
    {
        // Arrange - test certs don't have Microsoft EKUs
        var options = new CertificateSigningOptions();
        var chain = new[] { TestCert };

        // Act & Assert - Will throw because DID builder requires a policy
        Assert.Throws<InvalidOperationException>(() =>
            options.ConfigureForAzureScitt(chain));
    }

    #endregion

    #region ConfigureForAzureScitt Action Overload Tests

    [Test]
    public void ConfigureForAzureScitt_WithActionOverload_WithNullConfigureAction_ThrowsArgumentNullException()
    {
        // Arrange
        var options = new CertificateSigningOptions();
        var chain = new[] { TestCert };

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            options.ConfigureForAzureScitt(chain, (Action<CwtClaims>)null!));

        Assert.That(ex.ParamName, Is.EqualTo("configureClaimsAction"));
    }

    [Test]
    public void ConfigureForAzureScitt_WithActionOverload_WithNullOptions_ThrowsArgumentNullException()
    {
        // Arrange
        var chain = new[] { TestCert };

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            ScittExtensions.ConfigureForAzureScitt(null!, chain, claims => { }));

        Assert.That(ex.ParamName, Is.EqualTo("options"));
    }

    [Test]
    public void ConfigureForAzureScitt_WithActionOverload_WithNullChain_ThrowsArgumentNullException()
    {
        // Arrange
        var options = new CertificateSigningOptions();

        // Act & Assert
        var ex = Assert.Throws<ArgumentNullException>(() =>
            options.ConfigureForAzureScitt(null!, claims => { }));

        Assert.That(ex.ParamName, Is.EqualTo("certificateChain"));
    }

    #endregion

    #region Success Path Tests with Microsoft EKUs

    [Test]
    public void ConfigureForAzureScitt_WithMicrosoftEku_ConfiguresScittCompliance()
    {
        // Arrange
        var options = new CertificateSigningOptions();
        using var certWithEku = TestCertificateUtils.CreateCertificate(
            "ScittTestWithEku",
            customEkus: new[] { MicrosoftCodeSigningEku });
        var chain = new[] { certWithEku };

        // Act
        var result = options.ConfigureForAzureScitt(chain);

        // Assert
        Assert.That(result, Is.SameAs(options));
        Assert.That(options.EnableScittCompliance, Is.True);
        Assert.That(options.CustomCwtClaims, Is.Not.Null);
        Assert.That(options.CustomCwtClaims!.Issuer, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(options.CustomCwtClaims.Issuer, Does.Contain("::eku:"));
        Assert.That(options.CustomCwtClaims.IssuedAt, Is.Not.Null);
        Assert.That(options.CustomCwtClaims.NotBefore, Is.Not.Null);
    }

    [Test]
    public void ConfigureForAzureScitt_WithMicrosoftEku_SetsTimestamps()
    {
        // Arrange
        var options = new CertificateSigningOptions();
        using var certWithEku = TestCertificateUtils.CreateCertificate(
            "ScittTimestampTest",
            customEkus: new[] { MicrosoftCodeSigningEku });
        var chain = new[] { certWithEku };
        var beforeCall = DateTimeOffset.UtcNow;

        // Act
        options.ConfigureForAzureScitt(chain);

        var afterCall = DateTimeOffset.UtcNow;

        // Assert
        Assert.That(options.CustomCwtClaims, Is.Not.Null);
        Assert.That(options.CustomCwtClaims!.IssuedAt!.Value, Is.InRange(beforeCall, afterCall));
        Assert.That(options.CustomCwtClaims.NotBefore!.Value, Is.InRange(beforeCall, afterCall));
    }

    [Test]
    public void ConfigureForAzureScitt_WithActionOverload_AllowsClaimCustomization()
    {
        // Arrange
        var options = new CertificateSigningOptions();
        using var certWithEku = TestCertificateUtils.CreateCertificate(
            "ScittCustomClaimsTest",
            customEkus: new[] { MicrosoftCodeSigningEku });
        var chain = new[] { certWithEku };
        var customSubject = "custom-subject";
        var customAudience = "custom-audience";

        // Act
        options.ConfigureForAzureScitt(chain, claims =>
        {
            claims.Subject = customSubject;
            claims.Audience = customAudience;
        });

        // Assert
        Assert.That(options.EnableScittCompliance, Is.True);
        Assert.That(options.CustomCwtClaims, Is.Not.Null);
        Assert.That(options.CustomCwtClaims!.Subject, Is.EqualTo(customSubject));
        Assert.That(options.CustomCwtClaims.Audience, Is.EqualTo(customAudience));
        // Original claims should still be set
        Assert.That(options.CustomCwtClaims.Issuer, Does.StartWith("did:x509:0:sha256:"));
        Assert.That(options.CustomCwtClaims.IssuedAt, Is.Not.Null);
    }

    [Test]
    public void ConfigureForAzureScitt_WithChain_GeneratesCorrectDidX509()
    {
        // Arrange
        var options = new CertificateSigningOptions();
        using var rootCert = TestCertificateUtils.CreateCertificate("ScittRoot");
        using var leafCert = TestCertificateUtils.CreateCertificate(
            "ScittLeaf",
            issuingCa: rootCert,
            customEkus: new[] { MicrosoftCodeSigningEku });
        var chain = new[] { leafCert, rootCert };

        // Act
        options.ConfigureForAzureScitt(chain);

        // Assert
        Assert.That(options.CustomCwtClaims, Is.Not.Null);
        Assert.That(options.CustomCwtClaims!.Issuer, Does.Contain(MicrosoftCodeSigningEku));
    }

    [Test]
    public void ConfigureForAzureScitt_ReturnsSameOptionsForFluent()
    {
        // Arrange
        var options = new CertificateSigningOptions();
        using var certWithEku = TestCertificateUtils.CreateCertificate(
            "FluentTest",
            customEkus: new[] { MicrosoftCodeSigningEku });
        var chain = new[] { certWithEku };

        // Act
        var result = options.ConfigureForAzureScitt(chain);

        // Assert - fluent interface returns same instance
        Assert.That(result, Is.SameAs(options));
    }

    [Test]
    public void ConfigureForAzureScitt_WithActionOverload_ReturnsSameOptionsForFluent()
    {
        // Arrange
        var options = new CertificateSigningOptions();
        using var certWithEku = TestCertificateUtils.CreateCertificate(
            "FluentActionTest",
            customEkus: new[] { MicrosoftCodeSigningEku });
        var chain = new[] { certWithEku };

        // Act
        var result = options.ConfigureForAzureScitt(chain, claims => { });

        // Assert - fluent interface returns same instance
        Assert.That(result, Is.SameAs(options));
    }

    #endregion
}
