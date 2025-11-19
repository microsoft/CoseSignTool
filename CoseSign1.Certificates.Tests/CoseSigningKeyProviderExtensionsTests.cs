// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

using CoseSign1.Certificates.Extensions;
using CoseSign1.Headers;

namespace CoseSign1.Certificates.Tests;

/// <summary>
/// Tests for <see cref="CoseSigningKeyProviderExtensions"/>
/// </summary>
public class CoseSigningKeyProviderExtensionsTests
{
    /// <summary>
    /// Tests CreateHeaderExtenderWithDefaultCWTClaims with null provider throws ArgumentNullException
    /// </summary>
    [Test]
    public void TestCreateHeaderExtenderWithDefaultCWTClaims_NullProvider_ThrowsArgumentNullException()
    {
        CertificateCoseSigningKeyProvider? nullProvider = null;

        Action act = () => nullProvider!.CreateHeaderExtenderWithDefaultCWTClaims();
        
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("certificateProvider");
    }

    /// <summary>
    /// Tests CreateHeaderExtenderWithDefaultCWTClaims creates valid extender
    /// </summary>
    [Test]
    public void TestCreateHeaderExtenderWithDefaultCWTClaims_ValidProvider_ReturnsExtender()
    {
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate("TestCert");
        X509Certificate2CoseSigningKeyProvider provider = new(cert);

        ICoseHeaderExtender extender = provider.CreateHeaderExtenderWithDefaultCWTClaims();

        extender.Should().NotBeNull();
        extender.Should().BeOfType<X509CertificateWithCWTClaimsHeaderExtender>();

        cert.Dispose();
    }

    /// <summary>
    /// Tests CreateHeaderExtenderWithCustomCWTClaims with null provider throws ArgumentNullException
    /// </summary>
    [Test]
    public void TestCreateHeaderExtenderWithCustomCWTClaims_NullProvider_ThrowsArgumentNullException()
    {
        CertificateCoseSigningKeyProvider? nullProvider = null;
        CWTClaimsHeaderExtender? customClaims = new();

        Action act = () => nullProvider!.CreateHeaderExtenderWithCustomCWTClaims(customClaims);
        
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("certificateProvider");
    }

    /// <summary>
    /// Tests CreateHeaderExtenderWithCustomCWTClaims with valid provider and null custom claims
    /// </summary>
    [Test]
    public void TestCreateHeaderExtenderWithCustomCWTClaims_NullCustomClaims_ReturnsExtenderWithDefaults()
    {
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate("TestCert");
        X509Certificate2CoseSigningKeyProvider provider = new(cert);

        ICoseHeaderExtender extender = provider.CreateHeaderExtenderWithCustomCWTClaims(null);

        extender.Should().NotBeNull();
        extender.Should().BeOfType<X509CertificateWithCWTClaimsHeaderExtender>();

        cert.Dispose();
    }

    /// <summary>
    /// Tests CreateHeaderExtenderWithCustomCWTClaims with valid provider and custom claims
    /// </summary>
    [Test]
    public void TestCreateHeaderExtenderWithCustomCWTClaims_WithCustomClaims_ReturnsExtender()
    {
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate("TestCert");
        X509Certificate2CoseSigningKeyProvider provider = new(cert);
        
        CWTClaimsHeaderExtender customClaims = new();
        customClaims.SetIssuer("custom-issuer");
        customClaims.SetSubject("custom-subject");

        ICoseHeaderExtender extender = provider.CreateHeaderExtenderWithCustomCWTClaims(customClaims);

        extender.Should().NotBeNull();
        extender.Should().BeOfType<X509CertificateWithCWTClaimsHeaderExtender>();

        cert.Dispose();
    }

    /// <summary>
    /// Tests CreateHeaderExtenderWithCWTClaims with null provider throws ArgumentNullException
    /// </summary>
    [Test]
    public void TestCreateHeaderExtenderWithCWTClaims_NullProvider_ThrowsArgumentNullException()
    {
        CertificateCoseSigningKeyProvider? nullProvider = null;

        Action act = () => nullProvider!.CreateHeaderExtenderWithCWTClaims();
        
        act.Should().Throw<ArgumentNullException>()
            .WithParameterName("certificateProvider");
    }

    /// <summary>
    /// Tests CreateHeaderExtenderWithCWTClaims with both issuer and subject null uses defaults
    /// </summary>
    [Test]
    public void TestCreateHeaderExtenderWithCWTClaims_BothNull_UsesDefaults()
    {
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate("TestCert");
        X509Certificate2CoseSigningKeyProvider provider = new(cert);

        ICoseHeaderExtender extender = provider.CreateHeaderExtenderWithCWTClaims(null, null);

        extender.Should().NotBeNull();
        extender.Should().BeOfType<X509CertificateWithCWTClaimsHeaderExtender>();

        cert.Dispose();
    }

    /// <summary>
    /// Tests CreateHeaderExtenderWithCWTClaims with custom issuer and null subject
    /// </summary>
    [Test]
    public void TestCreateHeaderExtenderWithCWTClaims_CustomIssuerNullSubject_UsesDefaultSubject()
    {
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate("TestCert");
        X509Certificate2CoseSigningKeyProvider provider = new(cert);

        ICoseHeaderExtender extender = provider.CreateHeaderExtenderWithCWTClaims("custom-issuer", null);

        extender.Should().NotBeNull();
        extender.Should().BeOfType<X509CertificateWithCWTClaimsHeaderExtender>();

        cert.Dispose();
    }

    /// <summary>
    /// Tests CreateHeaderExtenderWithCWTClaims with null issuer and custom subject
    /// </summary>
    [Test]
    public void TestCreateHeaderExtenderWithCWTClaims_NullIssuerCustomSubject_UsesProviderIssuer()
    {
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate("TestCert");
        X509Certificate2CoseSigningKeyProvider provider = new(cert);

        ICoseHeaderExtender extender = provider.CreateHeaderExtenderWithCWTClaims(null, "custom-subject");

        extender.Should().NotBeNull();
        extender.Should().BeOfType<X509CertificateWithCWTClaimsHeaderExtender>();

        cert.Dispose();
    }

    /// <summary>
    /// Tests CreateHeaderExtenderWithCWTClaims with both custom issuer and subject
    /// </summary>
    [Test]
    public void TestCreateHeaderExtenderWithCWTClaims_CustomIssuerAndSubject_UsesCustomValues()
    {
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate("TestCert");
        X509Certificate2CoseSigningKeyProvider provider = new(cert);

        ICoseHeaderExtender extender = provider.CreateHeaderExtenderWithCWTClaims("custom-issuer", "custom-subject");

        extender.Should().NotBeNull();
        extender.Should().BeOfType<X509CertificateWithCWTClaimsHeaderExtender>();

        cert.Dispose();
    }

    /// <summary>
    /// Tests CreateHeaderExtenderWithCWTClaims when provider.Issuer is null
    /// Should use the custom subject but won't set issuer since provider doesn't have one
    /// </summary>
    [Test]
    public void TestCreateHeaderExtenderWithCWTClaims_ProviderIssuerNull_ThrowsException()
    {
        // Create a provider with a simple certificate that won't have a chain
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate("TestCert");
        TestCertificateProviderWithNullIssuer provider = new(cert);

        // When issuer is null and provider doesn't provide one, it should throw
        Action act = () => provider.CreateHeaderExtenderWithCWTClaims(null, "custom-subject");
        
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*Certificate provider did not return a valid issuer value*");

        cert.Dispose();
    }

    /// <summary>
    /// Tests CreateHeaderExtenderWithCWTClaims when provider.Issuer is empty string
    /// Should throw exception since empty issuer is not valid
    /// </summary>
    [Test]
    public void TestCreateHeaderExtenderWithCWTClaims_ProviderIssuerEmpty_ThrowsException()
    {
        X509Certificate2 cert = TestCertificateUtils.CreateCertificate("TestCert");
        TestCertificateProviderWithEmptyIssuer provider = new(cert);

        // When issuer is null and provider provides empty string, it should throw
        Action act = () => provider.CreateHeaderExtenderWithCWTClaims(null, "custom-subject");
        
        act.Should().Throw<InvalidOperationException>()
            .WithMessage("*Certificate provider did not return a valid issuer value*");

        cert.Dispose();
    }

    /// <summary>
    /// Helper test provider that returns null for Issuer
    /// </summary>
    private class TestCertificateProviderWithNullIssuer : X509Certificate2CoseSigningKeyProvider
    {
        public TestCertificateProviderWithNullIssuer(X509Certificate2 signingCertificate) 
            : base(signingCertificate)
        {
        }

        public override string? Issuer => null;
    }

    /// <summary>
    /// Helper test provider that returns empty string for Issuer
    /// </summary>
    private class TestCertificateProviderWithEmptyIssuer : X509Certificate2CoseSigningKeyProvider
    {
        public TestCertificateProviderWithEmptyIssuer(X509Certificate2 signingCertificate) 
            : base(signingCertificate)
        {
        }

        public override string? Issuer => string.Empty;
    }
}
